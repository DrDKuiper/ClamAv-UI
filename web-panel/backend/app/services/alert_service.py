import smtplib
import logging
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from typing import List, Dict, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from app.models.models import Alert, User, ServerMetric, ScanResult
from app.core.config import settings
from app.services.clamav_service import SystemMonitorService
import asyncio

logger = logging.getLogger(__name__)

class AlertService:
    """Serviço para gerenciamento de alertas e notificações"""
    
    def __init__(self):
        self.smtp_host = settings.SMTP_HOST
        self.smtp_port = settings.SMTP_PORT
        self.smtp_user = settings.SMTP_USER
        self.smtp_password = settings.SMTP_PASSWORD
        self.smtp_tls = settings.SMTP_TLS
        self.alert_recipients = settings.ALERT_EMAIL_RECIPIENTS
    
    def create_alert(
        self, 
        db: Session,
        title: str,
        message: str,
        alert_type: str,
        severity: str = "medium",
        server_hostname: str = None,
        metadata: Dict = None
    ) -> Alert:
        """Cria um novo alerta"""
        try:
            alert = Alert(
                title=title,
                message=message,
                alert_type=alert_type,
                severity=severity,
                server_hostname=server_hostname,
                metadata=metadata or {}
            )
            
            db.add(alert)
            db.commit()
            db.refresh(alert)
            
            # Enviar notificação por email se for crítico
            if severity in ["high", "critical"]:
                asyncio.create_task(self._send_email_notification(alert))
            
            logger.info(f"Alerta criado: {title} - {severity}")
            return alert
        
        except Exception as e:
            logger.error(f"Erro ao criar alerta: {e}")
            db.rollback()
            raise
    
    async def _send_email_notification(self, alert: Alert):
        """Envia notificação por email"""
        try:
            if not self.alert_recipients:
                return
            
            subject = f"[ClamAV Alert] {alert.severity.upper()}: {alert.title}"
            
            body = f"""
            Alerta do Sistema ClamAV
            
            Título: {alert.title}
            Tipo: {alert.alert_type}
            Severidade: {alert.severity.upper()}
            Servidor: {alert.server_hostname or 'N/A'}
            Data: {alert.created_at.strftime('%Y-%m-%d %H:%M:%S')}
            
            Mensagem:
            {alert.message}
            
            ---
            Sistema de Monitoramento ClamAV
            """
            
            await self._send_email(self.alert_recipients, subject, body)
        
        except Exception as e:
            logger.error(f"Erro ao enviar notificação por email: {e}")
    
    async def _send_email(self, recipients: List[str], subject: str, body: str):
        """Envia email usando SMTP"""
        try:
            msg = MimeMultipart()
            msg['From'] = self.smtp_user
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = subject
            
            msg.attach(MimeText(body, 'plain'))
            
            server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            if self.smtp_tls:
                server.starttls()
            
            if self.smtp_user and self.smtp_password:
                server.login(self.smtp_user, self.smtp_password)
            
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email enviado para {recipients}")
        
        except Exception as e:
            logger.error(f"Erro ao enviar email: {e}")
    
    def check_threat_alerts(self, db: Session) -> List[Alert]:
        """Verifica e cria alertas para ameaças detectadas"""
        try:
            alerts_created = []
            
            # Buscar ameaças detectadas na última hora
            one_hour_ago = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
            
            recent_threats = db.query(ScanResult).filter(
                ScanResult.threat_found == True,
                ScanResult.scan_date >= one_hour_ago
            ).all()
            
            if recent_threats:
                threat_count = len(recent_threats)
                critical_threats = [t for t in recent_threats if t.threat_level == "critical"]
                
                # Criar alerta para ameaças críticas
                if critical_threats:
                    alert = self.create_alert(
                        db=db,
                        title=f"{len(critical_threats)} Ameaças Críticas Detectadas",
                        message=f"Foram detectadas {len(critical_threats)} ameaças críticas na última hora.",
                        alert_type="threat",
                        severity="critical",
                        metadata={
                            "threat_count": len(critical_threats),
                            "threats": [{"path": t.file_path, "threat": t.threat_name} for t in critical_threats[:5]]
                        }
                    )
                    alerts_created.append(alert)
                
                # Alerta geral se muitas ameaças
                elif threat_count > 10:
                    alert = self.create_alert(
                        db=db,
                        title=f"{threat_count} Ameaças Detectadas",
                        message=f"Foram detectadas {threat_count} ameaças na última hora.",
                        alert_type="threat",
                        severity="high",
                        metadata={"threat_count": threat_count}
                    )
                    alerts_created.append(alert)
            
            return alerts_created
        
        except Exception as e:
            logger.error(f"Erro ao verificar alertas de ameaças: {e}")
            return []
    
    def check_system_alerts(self, db: Session) -> List[Alert]:
        """Verifica e cria alertas para problemas do sistema"""
        try:
            alerts_created = []
            
            # Verificar métricas do sistema
            metrics = SystemMonitorService.get_system_metrics()
            
            # Alerta de CPU alta
            if metrics.get("cpu_usage", 0) > 90:
                alert = self.create_alert(
                    db=db,
                    title="Uso de CPU Crítico",
                    message=f"Uso de CPU está em {metrics['cpu_usage']:.1f}%",
                    alert_type="system",
                    severity="high",
                    metadata={"cpu_usage": metrics["cpu_usage"]}
                )
                alerts_created.append(alert)
            
            # Alerta de memória alta
            if metrics.get("memory_usage", 0) > 90:
                alert = self.create_alert(
                    db=db,
                    title="Uso de Memória Crítico",
                    message=f"Uso de memória está em {metrics['memory_usage']:.1f}%",
                    alert_type="system",
                    severity="high",
                    metadata={"memory_usage": metrics["memory_usage"]}
                )
                alerts_created.append(alert)
            
            # Alerta de disco cheio
            if metrics.get("disk_usage", 0) > 95:
                alert = self.create_alert(
                    db=db,
                    title="Disco Quase Cheio",
                    message=f"Uso de disco está em {metrics['disk_usage']:.1f}%",
                    alert_type="system",
                    severity="critical",
                    metadata={"disk_usage": metrics["disk_usage"]}
                )
                alerts_created.append(alert)
            
            return alerts_created
        
        except Exception as e:
            logger.error(f"Erro ao verificar alertas do sistema: {e}")
            return []
    
    def check_server_health_alerts(self, db: Session) -> List[Alert]:
        """Verifica e cria alertas para saúde dos servidores"""
        try:
            from app.models.models import Server
            alerts_created = []
            
            # Buscar servidores offline há mais de 5 minutos
            five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
            
            offline_servers = db.query(Server).filter(
                Server.status == "offline",
                Server.last_seen < five_minutes_ago
            ).all()
            
            for server in offline_servers:
                # Verificar se já existe alerta recente para este servidor
                recent_alert = db.query(Alert).filter(
                    Alert.alert_type == "server",
                    Alert.server_hostname == server.hostname,
                    Alert.created_at >= five_minutes_ago,
                    Alert.is_resolved == False
                ).first()
                
                if not recent_alert:
                    alert = self.create_alert(
                        db=db,
                        title=f"Servidor Offline: {server.name}",
                        message=f"O servidor {server.name} ({server.hostname}) está offline há mais de 5 minutos.",
                        alert_type="server",
                        severity="high",
                        server_hostname=server.hostname,
                        metadata={"server_id": server.id, "last_seen": server.last_seen.isoformat()}
                    )
                    alerts_created.append(alert)
            
            return alerts_created
        
        except Exception as e:
            logger.error(f"Erro ao verificar alertas de saúde dos servidores: {e}")
            return []
    
    def resolve_alert(self, db: Session, alert_id: int, user_id: int) -> bool:
        """Marca um alerta como resolvido"""
        try:
            alert = db.query(Alert).filter(Alert.id == alert_id).first()
            if not alert:
                return False
            
            alert.is_resolved = True
            alert.resolved_by = user_id
            alert.resolved_at = datetime.utcnow()
            
            db.commit()
            
            logger.info(f"Alerta {alert_id} resolvido pelo usuário {user_id}")
            return True
        
        except Exception as e:
            logger.error(f"Erro ao resolver alerta {alert_id}: {e}")
            db.rollback()
            return False
    
    def mark_alert_as_read(self, db: Session, alert_id: int) -> bool:
        """Marca um alerta como lido"""
        try:
            alert = db.query(Alert).filter(Alert.id == alert_id).first()
            if not alert:
                return False
            
            alert.is_read = True
            db.commit()
            
            return True
        
        except Exception as e:
            logger.error(f"Erro ao marcar alerta como lido: {e}")
            db.rollback()
            return False
    
    def get_active_alerts(self, db: Session, limit: int = 50) -> List[Alert]:
        """Obtém alertas ativos"""
        try:
            return db.query(Alert).filter(
                Alert.is_resolved == False
            ).order_by(
                Alert.created_at.desc()
            ).limit(limit).all()
        
        except Exception as e:
            logger.error(f"Erro ao obter alertas ativos: {e}")
            return []
    
    def get_alert_statistics(self, db: Session) -> Dict:
        """Obtém estatísticas de alertas"""
        try:
            from datetime import timedelta
            
            total_alerts = db.query(Alert).count()
            active_alerts = db.query(Alert).filter(Alert.is_resolved == False).count()
            
            # Alertas por severidade
            severity_counts = {}
            for severity in ["low", "medium", "high", "critical"]:
                count = db.query(Alert).filter(
                    Alert.severity == severity,
                    Alert.is_resolved == False
                ).count()
                severity_counts[severity] = count
            
            # Alertas por tipo
            type_counts = {}
            for alert_type in ["threat", "system", "server", "update"]:
                count = db.query(Alert).filter(
                    Alert.alert_type == alert_type,
                    Alert.is_resolved == False
                ).count()
                type_counts[alert_type] = count
            
            # Alertas nas últimas 24 horas
            yesterday = datetime.utcnow() - timedelta(hours=24)
            recent_alerts = db.query(Alert).filter(
                Alert.created_at >= yesterday
            ).count()
            
            return {
                "total_alerts": total_alerts,
                "active_alerts": active_alerts,
                "severity_distribution": severity_counts,
                "type_distribution": type_counts,
                "alerts_24h": recent_alerts
            }
        
        except Exception as e:
            logger.error(f"Erro ao obter estatísticas de alertas: {e}")
            return {}
