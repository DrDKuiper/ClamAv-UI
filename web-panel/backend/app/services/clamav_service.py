import socket
import asyncio
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import psutil
import subprocess
import os
from app.core.config import settings

logger = logging.getLogger(__name__)

class ClamAVService:
    """Serviço para comunicação com ClamAV daemon"""
    
    def __init__(self, host: str = None, port: int = None, socket_path: str = None):
        self.host = host or settings.CLAMD_HOST
        self.port = port or settings.CLAMD_PORT
        self.socket_path = socket_path or settings.CLAMD_SOCKET
        self.timeout = 30
    
    async def _send_command(self, command: str) -> str:
        """Envia comando para o daemon ClamAV"""
        try:
            if self.socket_path and os.path.exists(self.socket_path):
                # Usar socket Unix se disponível
                reader, writer = await asyncio.open_unix_connection(self.socket_path)
            else:
                # Usar socket TCP
                reader, writer = await asyncio.open_connection(self.host, self.port)
            
            # Enviar comando
            writer.write(f"{command}\n".encode())
            await writer.drain()
            
            # Ler resposta
            response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            
            writer.close()
            await writer.wait_closed()
            
            return response.decode().strip()
        
        except Exception as e:
            logger.error(f"Erro ao comunicar com ClamAV: {e}")
            raise
    
    async def ping(self) -> bool:
        """Verifica se o daemon está respondendo"""
        try:
            response = await self._send_command("PING")
            return response == "PONG"
        except Exception:
            return False
    
    async def scan_file(self, file_path: str) -> Dict:
        """Escaneia um arquivo específico"""
        try:
            command = f"SCAN {file_path}"
            response = await self._send_command(command)
            
            if "FOUND" in response:
                parts = response.split(": ")
                if len(parts) >= 2:
                    threat_name = parts[1].replace(" FOUND", "")
                    return {
                        "infected": True,
                        "threat": threat_name,
                        "path": file_path
                    }
            
            return {
                "infected": False,
                "threat": None,
                "path": file_path
            }
        
        except Exception as e:
            logger.error(f"Erro ao escanear arquivo {file_path}: {e}")
            raise
    
    async def scan_directory(self, directory_path: str, recursive: bool = True) -> List[Dict]:
        """Escaneia um diretório"""
        try:
            command = "MULTISCAN" if recursive else "SCAN"
            command += f" {directory_path}"
            
            response = await self._send_command(command)
            results = []
            
            for line in response.split('\n'):
                if line.strip():
                    if "FOUND" in line:
                        parts = line.split(": ")
                        if len(parts) >= 2:
                            file_path = parts[0]
                            threat_name = parts[1].replace(" FOUND", "")
                            results.append({
                                "infected": True,
                                "threat": threat_name,
                                "path": file_path
                            })
                    elif "OK" in line:
                        file_path = line.replace(": OK", "")
                        results.append({
                            "infected": False,
                            "threat": None,
                            "path": file_path
                        })
            
            return results
        
        except Exception as e:
            logger.error(f"Erro ao escanear diretório {directory_path}: {e}")
            raise
    
    async def get_version(self) -> Dict:
        """Obtém versão do ClamAV"""
        try:
            response = await self._send_command("VERSION")
            lines = response.split('\n')
            
            version_info = {}
            for line in lines:
                if "ClamAV" in line:
                    version_info["clamav_version"] = line.strip()
                elif "Database" in line:
                    version_info["database_version"] = line.strip()
            
            return version_info
        
        except Exception as e:
            logger.error(f"Erro ao obter versão: {e}")
            raise
    
    async def get_stats(self) -> Dict:
        """Obtém estatísticas do daemon"""
        try:
            response = await self._send_command("STATS")
            stats = {}
            
            for line in response.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    stats[key.strip().lower().replace(' ', '_')] = value.strip()
            
            return stats
        
        except Exception as e:
            logger.error(f"Erro ao obter estatísticas: {e}")
            raise
    
    async def reload_database(self) -> bool:
        """Recarrega o banco de dados de assinaturas"""
        try:
            response = await self._send_command("RELOAD")
            return "RELOADING" in response
        except Exception as e:
            logger.error(f"Erro ao recarregar banco de dados: {e}")
            return False
    
    async def shutdown(self) -> bool:
        """Para o daemon"""
        try:
            response = await self._send_command("SHUTDOWN")
            return True
        except Exception as e:
            logger.error(f"Erro ao parar daemon: {e}")
            return False

class SystemMonitorService:
    """Serviço para monitoramento do sistema"""
    
    @staticmethod
    def get_system_metrics() -> Dict:
        """Obtém métricas do sistema"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                "cpu_usage": cpu_percent,
                "memory_usage": memory.percent,
                "memory_total": memory.total,
                "memory_available": memory.available,
                "disk_usage": disk.percent,
                "disk_total": disk.total,
                "disk_free": disk.free,
                "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0],
                "uptime": psutil.boot_time(),
                "timestamp": datetime.utcnow()
            }
        except Exception as e:
            logger.error(f"Erro ao obter métricas do sistema: {e}")
            return {}
    
    @staticmethod
    def get_process_info(process_name: str = "clamd") -> Dict:
        """Obtém informações sobre processo específico"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                if process_name in proc.info['name']:
                    return {
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "cpu_percent": proc.info['cpu_percent'],
                        "memory_percent": proc.info['memory_percent'],
                        "status": proc.status(),
                        "create_time": proc.create_time(),
                        "cmdline": proc.cmdline() if proc.cmdline() else []
                    }
            return {}
        except Exception as e:
            logger.error(f"Erro ao obter informações do processo {process_name}: {e}")
            return {}

class QuarantineService:
    """Serviço para gerenciamento de quarentena"""
    
    def __init__(self, quarantine_path: str = None):
        self.quarantine_path = quarantine_path or settings.QUARANTINE_PATH
        self._ensure_quarantine_directory()
    
    def _ensure_quarantine_directory(self):
        """Garante que o diretório de quarentena existe"""
        try:
            os.makedirs(self.quarantine_path, exist_ok=True)
            os.chmod(self.quarantine_path, 0o700)  # Apenas owner pode acessar
        except Exception as e:
            logger.error(f"Erro ao criar diretório de quarentena: {e}")
    
    def quarantine_file(self, source_path: str, threat_name: str) -> str:
        """Move arquivo para quarentena"""
        try:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = os.path.basename(source_path)
            safe_threat_name = threat_name.replace("/", "_").replace("\\", "_")
            
            quarantine_filename = f"{timestamp}_{safe_threat_name}_{filename}"
            quarantine_file_path = os.path.join(self.quarantine_path, quarantine_filename)
            
            # Mover arquivo
            os.rename(source_path, quarantine_file_path)
            
            # Remover permissões de execução
            os.chmod(quarantine_file_path, 0o600)
            
            logger.info(f"Arquivo {source_path} movido para quarentena: {quarantine_file_path}")
            return quarantine_file_path
        
        except Exception as e:
            logger.error(f"Erro ao colocar arquivo em quarentena: {e}")
            raise
    
    def restore_file(self, quarantine_path: str, original_path: str) -> bool:
        """Restaura arquivo da quarentena"""
        try:
            if not os.path.exists(quarantine_path):
                raise FileNotFoundError("Arquivo não encontrado na quarentena")
            
            # Criar diretório de destino se não existir
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            
            # Mover arquivo de volta
            os.rename(quarantine_path, original_path)
            
            logger.info(f"Arquivo restaurado da quarentena: {original_path}")
            return True
        
        except Exception as e:
            logger.error(f"Erro ao restaurar arquivo: {e}")
            return False
    
    def delete_quarantine_file(self, quarantine_path: str) -> bool:
        """Remove arquivo permanentemente da quarentena"""
        try:
            if os.path.exists(quarantine_path):
                os.remove(quarantine_path)
                logger.info(f"Arquivo removido permanentemente: {quarantine_path}")
                return True
            return False
        
        except Exception as e:
            logger.error(f"Erro ao remover arquivo da quarentena: {e}")
            return False
    
    def get_quarantine_size(self) -> int:
        """Obtém tamanho total da quarentena em bytes"""
        try:
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(self.quarantine_path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    total_size += os.path.getsize(filepath)
            return total_size
        
        except Exception as e:
            logger.error(f"Erro ao calcular tamanho da quarentena: {e}")
            return 0
    
    def cleanup_old_files(self, days_old: int = 30) -> int:
        """Remove arquivos antigos da quarentena"""
        try:
            cutoff_time = datetime.utcnow().timestamp() - (days_old * 24 * 60 * 60)
            removed_count = 0
            
            for filename in os.listdir(self.quarantine_path):
                filepath = os.path.join(self.quarantine_path, filename)
                if os.path.getmtime(filepath) < cutoff_time:
                    os.remove(filepath)
                    removed_count += 1
            
            logger.info(f"Removidos {removed_count} arquivos antigos da quarentena")
            return removed_count
        
        except Exception as e:
            logger.error(f"Erro ao limpar arquivos antigos: {e}")
            return 0
