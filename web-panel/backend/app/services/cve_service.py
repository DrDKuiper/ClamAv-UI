import requests
import logging
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.models.models import CVEVulnerability
from app.core.config import settings
import time

logger = logging.getLogger(__name__)

class CVEService:
    """Serviço para integração com APIs de vulnerabilidades CVE"""
    
    def __init__(self):
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = settings.NVD_API_KEY
        self.session = requests.Session()
        
        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})
    
    def search_cves(
        self, 
        keyword: str = None,
        cpe_name: str = None,
        cvss_severity: str = None,
        pub_start_date: datetime = None,
        pub_end_date: datetime = None,
        results_per_page: int = 20
    ) -> Dict:
        """Busca CVEs na base de dados NVD"""
        try:
            params = {
                "resultsPerPage": results_per_page,
                "startIndex": 0
            }
            
            if keyword:
                params["keywordSearch"] = keyword
            
            if cpe_name:
                params["cpeName"] = cpe_name
            
            if cvss_severity:
                params["cvssV3Severity"] = cvss_severity
            
            if pub_start_date:
                params["pubStartDate"] = pub_start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            
            if pub_end_date:
                params["pubEndDate"] = pub_end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            
            response = self.session.get(self.nvd_base_url, params=params, timeout=30)
            response.raise_for_status()
            
            # Rate limiting para API pública
            if not self.api_key:
                time.sleep(6)  # 10 requests per minute for public API
            else:
                time.sleep(0.6)  # 100 requests per minute for API key users
            
            return response.json()
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Erro ao buscar CVEs: {e}")
            return {"vulnerabilities": [], "totalResults": 0}
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """Obtém detalhes de um CVE específico"""
        try:
            params = {"cveId": cve_id}
            response = self.session.get(self.nvd_base_url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            if data.get("vulnerabilities"):
                return data["vulnerabilities"][0]
            
            return None
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Erro ao obter detalhes do CVE {cve_id}: {e}")
            return None
    
    def parse_cve_data(self, cve_data: Dict) -> Dict:
        """Processa dados de CVE para formato padronizado"""
        try:
            cve = cve_data.get("cve", {})
            
            # Informações básicas
            cve_id = cve.get("id", "")
            
            # Descrição
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Métricas CVSS
            metrics = cve_data.get("metrics", {})
            cvss_score = 0.0
            severity = "UNKNOWN"
            
            # Tentar CVSS v3.1 primeiro, depois v3.0, depois v2.0
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics and metrics[version]:
                    metric = metrics[version][0]
                    if version.startswith("cvssMetricV3"):
                        cvss_data = metric.get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", 0.0)
                        severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    else:  # v2.0
                        cvss_data = metric.get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", 0.0)
                        # Converter score v2 para severity
                        if cvss_score >= 7.0:
                            severity = "HIGH"
                        elif cvss_score >= 4.0:
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"
                    break
            
            # Datas
            published = cve.get("published", "")
            modified = cve.get("lastModified", "")
            
            published_date = None
            modified_date = None
            
            if published:
                published_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
            
            if modified:
                modified_date = datetime.fromisoformat(modified.replace('Z', '+00:00'))
            
            # Referências
            references = []
            for ref in cve.get("references", []):
                if ref.get("url"):
                    references.append(ref["url"])
            
            # Software afetado (CPEs)
            affected_software = []
            configurations = cve.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("criteria"):
                            affected_software.append(cpe_match["criteria"])
            
            return {
                "cve_id": cve_id,
                "description": description,
                "severity": severity,
                "cvss_score": cvss_score,
                "published_date": published_date,
                "modified_date": modified_date,
                "affected_software": affected_software,
                "references": references
            }
        
        except Exception as e:
            logger.error(f"Erro ao processar dados do CVE: {e}")
            return {}
    
    def update_cve_database(self, db: Session, days_back: int = 7) -> int:
        """Atualiza banco de dados local com CVEs recentes"""
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days_back)
            
            logger.info(f"Atualizando CVEs de {start_date} até {end_date}")
            
            updated_count = 0
            start_index = 0
            results_per_page = 100
            
            while True:
                # Buscar CVEs
                response_data = self.search_cves(
                    pub_start_date=start_date,
                    pub_end_date=end_date,
                    results_per_page=results_per_page
                )
                
                vulnerabilities = response_data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break
                
                # Processar cada CVE
                for vuln_data in vulnerabilities:
                    cve_data = self.parse_cve_data(vuln_data)
                    if not cve_data.get("cve_id"):
                        continue
                    
                    # Verificar se já existe no banco
                    existing_cve = db.query(CVEVulnerability).filter(
                        CVEVulnerability.cve_id == cve_data["cve_id"]
                    ).first()
                    
                    if existing_cve:
                        # Atualizar se modificado
                        if (cve_data.get("modified_date") and 
                            existing_cve.modified_date < cve_data["modified_date"]):
                            
                            for key, value in cve_data.items():
                                if key != "cve_id":
                                    setattr(existing_cve, key, value)
                            
                            existing_cve.updated_at = datetime.utcnow()
                            updated_count += 1
                    else:
                        # Criar novo registro
                        new_cve = CVEVulnerability(**cve_data)
                        db.add(new_cve)
                        updated_count += 1
                
                db.commit()
                
                # Verificar se há mais resultados
                total_results = response_data.get("totalResults", 0)
                start_index += results_per_page
                
                if start_index >= total_results:
                    break
            
            logger.info(f"Atualização concluída. {updated_count} CVEs processados.")
            return updated_count
        
        except Exception as e:
            logger.error(f"Erro ao atualizar banco de CVEs: {e}")
            db.rollback()
            return 0
    
    def search_software_vulnerabilities(
        self, 
        software_list: List[str], 
        db: Session,
        severity_filter: List[str] = None
    ) -> List[CVEVulnerability]:
        """Busca vulnerabilidades para lista de software"""
        try:
            vulnerabilities = []
            
            for software in software_list:
                # Buscar no banco local primeiro
                query = db.query(CVEVulnerability)
                
                # Filtrar por software (busca em affected_software JSON)
                query = query.filter(
                    CVEVulnerability.affected_software.op('?')(software)
                )
                
                # Filtrar por severidade se especificado
                if severity_filter:
                    query = query.filter(CVEVulnerability.severity.in_(severity_filter))
                
                # Ordenar por score CVSS (mais críticos primeiro)
                query = query.order_by(CVEVulnerability.cvss_score.desc())
                
                software_vulns = query.limit(10).all()
                vulnerabilities.extend(software_vulns)
            
            return vulnerabilities
        
        except Exception as e:
            logger.error(f"Erro ao buscar vulnerabilidades de software: {e}")
            return []
    
    def get_vulnerability_stats(self, db: Session) -> Dict:
        """Obtém estatísticas de vulnerabilidades"""
        try:
            total_cves = db.query(CVEVulnerability).count()
            
            # Contar por severidade
            severity_counts = {}
            for severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                count = db.query(CVEVulnerability).filter(
                    CVEVulnerability.severity == severity
                ).count()
                severity_counts[severity] = count
            
            # CVEs recentes (últimos 30 dias)
            recent_date = datetime.utcnow() - timedelta(days=30)
            recent_cves = db.query(CVEVulnerability).filter(
                CVEVulnerability.published_date >= recent_date
            ).count()
            
            # CVEs críticos recentes
            critical_recent = db.query(CVEVulnerability).filter(
                CVEVulnerability.published_date >= recent_date,
                CVEVulnerability.severity == "CRITICAL"
            ).count()
            
            return {
                "total_cves": total_cves,
                "severity_distribution": severity_counts,
                "recent_cves_30d": recent_cves,
                "critical_recent_30d": critical_recent,
                "last_update": datetime.utcnow()
            }
        
        except Exception as e:
            logger.error(f"Erro ao obter estatísticas de vulnerabilidades: {e}")
            return {}
