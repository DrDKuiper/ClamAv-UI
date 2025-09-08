from celery import Celery
from celery.schedules import crontab
import logging
from typing import Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import SessionLocal
from app.services.clamav_service import ClamAVService, QuarantineService
from app.services.cve_service import CVEService
from app.services.alert_service import AlertService
from app.models.models import ScheduledTask, TaskExecution, Server, TaskStatus
import subprocess
import os

logger = logging.getLogger(__name__)

# Configurar Celery
celery_app = Celery(
    "clamav_tasks",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["app.services.task_service"]
)

# Configurar agendamento de tarefas
celery_app.conf.beat_schedule = {
    # Verificar alertas a cada 5 minutos
    'check-alerts': {
        'task': 'app.services.task_service.check_system_alerts',
        'schedule': crontab(minute='*/5'),
    },
    # Atualizar CVEs a cada hora
    'update-cves': {
        'task': 'app.services.task_service.update_cve_database',
        'schedule': crontab(minute=0),
    },
    # Coletar métricas dos servidores a cada 2 minutos
    'collect-metrics': {
        'task': 'app.services.task_service.collect_server_metrics',
        'schedule': crontab(minute='*/2'),
    },
    # Limpeza de quarentena semanal
    'quarantine-cleanup': {
        'task': 'app.services.task_service.cleanup_quarantine',
        'schedule': crontab(hour=2, minute=0, day_of_week=0),  # Domingo às 2h
    },
    # Atualização de assinaturas diária
    'update-signatures': {
        'task': 'app.services.task_service.update_virus_signatures',
        'schedule': crontab(hour=3, minute=0),  # Todo dia às 3h
    },
}

celery_app.conf.timezone = 'UTC'

class TaskService:
    """Serviço para gerenciamento de tarefas agendadas"""
    
    @staticmethod
    def get_db() -> Session:
        """Obtém sessão do banco de dados"""
        return SessionLocal()
    
    @staticmethod
    def create_task_execution(
        db: Session, 
        task_id: int, 
        status: TaskStatus = TaskStatus.PENDING
    ) -> TaskExecution:
        """Cria registro de execução de tarefa"""
        execution = TaskExecution(
            task_id=task_id,
            status=status,
            started_at=datetime.utcnow() if status == TaskStatus.RUNNING else None
        )
        db.add(execution)
        db.commit()
        db.refresh(execution)
        return execution
    
    @staticmethod
    def update_task_execution(
        db: Session, 
        execution_id: int, 
        status: TaskStatus,
        output: str = None,
        error_message: str = None
    ):
        """Atualiza execução de tarefa"""
        execution = db.query(TaskExecution).filter(
            TaskExecution.id == execution_id
        ).first()
        
        if execution:
            execution.status = status
            if status == TaskStatus.COMPLETED or status == TaskStatus.FAILED:
                execution.completed_at = datetime.utcnow()
            if output:
                execution.output = output
            if error_message:
                execution.error_message = error_message
            
            db.commit()

# Tarefas Celery
@celery_app.task(bind=True)
def scan_directory_task(self, server_id: int, directory_path: str, recursive: bool = True):
    """Tarefa para escanear diretório"""
    db = TaskService.get_db()
    execution = None
    
    try:
        # Buscar servidor
        server = db.query(Server).filter(Server.id == server_id).first()
        if not server:
            raise ValueError(f"Servidor {server_id} não encontrado")
        
        # Criar registro de execução
        execution = TaskService.create_task_execution(db, self.request.id, TaskStatus.RUNNING)
        
        # Inicializar serviço ClamAV
        clamav = ClamAVService(
            host=server.ip_address,
            port=server.port,
            socket_path=server.socket_path
        )
        
        # Executar scan
        results = await clamav.scan_directory(directory_path, recursive)
        
        # Processar resultados
        threats_found = [r for r in results if r["infected"]]
        
        output = f"Scan concluído em {directory_path}\n"
        output += f"Arquivos escaneados: {len(results)}\n"
        output += f"Ameaças encontradas: {len(threats_found)}\n"
        
        if threats_found:
            output += "\nAmeaças detectadas:\n"
            for threat in threats_found:
                output += f"- {threat['path']}: {threat['threat']}\n"
        
        # Atualizar execução
        TaskService.update_task_execution(
            db, execution.id, TaskStatus.COMPLETED, output
        )
        
        # Criar alertas se necessário
        if threats_found:
            alert_service = AlertService()
            alert_service.create_alert(
                db=db,
                title=f"Ameaças Detectadas no Scan",
                message=f"Encontradas {len(threats_found)} ameaças no scan de {directory_path}",
                alert_type="threat",
                severity="high" if len(threats_found) > 5 else "medium",
                server_hostname=server.hostname,
                metadata={"scan_results": threats_found[:10]}
            )
        
        return {"status": "completed", "threats_found": len(threats_found)}
    
    except Exception as e:
        logger.error(f"Erro no scan: {e}")
        if execution:
            TaskService.update_task_execution(
                db, execution.id, TaskStatus.FAILED, error_message=str(e)
            )
        raise
    
    finally:
        db.close()

@celery_app.task
def update_virus_signatures():
    """Atualiza assinaturas de vírus usando freshclam"""
    db = TaskService.get_db()
    
    try:
        # Executar freshclam
        result = subprocess.run(
            ["freshclam", "--config-file=/etc/clamav/freshclam.conf"],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode == 0:
            logger.info("Assinaturas atualizadas com sucesso")
            
            # Notificar servidores para recarregar
            servers = db.query(Server).filter(Server.status == "online").all()
            for server in servers:
                try:
                    clamav = ClamAVService(
                        host=server.ip_address,
                        port=server.port,
                        socket_path=server.socket_path
                    )
                    await clamav.reload_database()
                except Exception as e:
                    logger.error(f"Erro ao recarregar banco no servidor {server.hostname}: {e}")
            
            return {"status": "completed", "output": result.stdout}
        else:
            logger.error(f"Erro ao atualizar assinaturas: {result.stderr}")
            return {"status": "failed", "error": result.stderr}
    
    except Exception as e:
        logger.error(f"Erro na atualização de assinaturas: {e}")
        return {"status": "failed", "error": str(e)}
    
    finally:
        db.close()

@celery_app.task
def collect_server_metrics():
    """Coleta métricas de todos os servidores"""
    db = TaskService.get_db()
    
    try:
        from app.services.clamav_service import SystemMonitorService
        from app.models.models import ServerMetric
        
        servers = db.query(Server).all()
        collected_count = 0
        
        for server in servers:
            try:
                # Verificar status do servidor
                clamav = ClamAVService(
                    host=server.ip_address,
                    port=server.port,
                    socket_path=server.socket_path
                )
                
                is_online = await clamav.ping()
                
                if is_online:
                    server.status = "online"
                    server.last_seen = datetime.utcnow()
                    
                    # Coletar métricas se for servidor local
                    if server.ip_address in ["localhost", "127.0.0.1"]:
                        metrics_data = SystemMonitorService.get_system_metrics()
                        
                        metric = ServerMetric(
                            server_id=server.id,
                            cpu_usage=metrics_data.get("cpu_usage"),
                            memory_usage=metrics_data.get("memory_usage"),
                            disk_usage=metrics_data.get("disk_usage"),
                            timestamp=datetime.utcnow()
                        )
                        db.add(metric)
                        collected_count += 1
                else:
                    server.status = "offline"
            
            except Exception as e:
                logger.error(f"Erro ao coletar métricas do servidor {server.hostname}: {e}")
                server.status = "error"
        
        db.commit()
        
        logger.info(f"Métricas coletadas de {collected_count} servidores")
        return {"status": "completed", "servers_monitored": collected_count}
    
    except Exception as e:
        logger.error(f"Erro na coleta de métricas: {e}")
        return {"status": "failed", "error": str(e)}
    
    finally:
        db.close()

@celery_app.task
def check_system_alerts():
    """Verifica e cria alertas do sistema"""
    db = TaskService.get_db()
    
    try:
        alert_service = AlertService()
        
        # Verificar diferentes tipos de alertas
        threat_alerts = alert_service.check_threat_alerts(db)
        system_alerts = alert_service.check_system_alerts(db)
        server_alerts = alert_service.check_server_health_alerts(db)
        
        total_alerts = len(threat_alerts) + len(system_alerts) + len(server_alerts)
        
        logger.info(f"Verificação de alertas concluída: {total_alerts} novos alertas")
        return {
            "status": "completed", 
            "new_alerts": total_alerts,
            "breakdown": {
                "threats": len(threat_alerts),
                "system": len(system_alerts),
                "servers": len(server_alerts)
            }
        }
    
    except Exception as e:
        logger.error(f"Erro na verificação de alertas: {e}")
        return {"status": "failed", "error": str(e)}
    
    finally:
        db.close()

@celery_app.task
def update_cve_database():
    """Atualiza banco de dados de CVEs"""
    db = TaskService.get_db()
    
    try:
        cve_service = CVEService()
        updated_count = cve_service.update_cve_database(db, days_back=1)
        
        logger.info(f"Banco de CVEs atualizado: {updated_count} registros")
        return {"status": "completed", "updated_cves": updated_count}
    
    except Exception as e:
        logger.error(f"Erro na atualização de CVEs: {e}")
        return {"status": "failed", "error": str(e)}
    
    finally:
        db.close()

@celery_app.task
def cleanup_quarantine():
    """Limpa arquivos antigos da quarentena"""
    try:
        quarantine_service = QuarantineService()
        removed_count = quarantine_service.cleanup_old_files(days_old=30)
        
        logger.info(f"Limpeza de quarentena concluída: {removed_count} arquivos removidos")
        return {"status": "completed", "files_removed": removed_count}
    
    except Exception as e:
        logger.error(f"Erro na limpeza de quarentena: {e}")
        return {"status": "failed", "error": str(e)}

@celery_app.task(bind=True)
def execute_custom_task(self, task_id: int):
    """Executa tarefa customizada"""
    db = TaskService.get_db()
    execution = None
    
    try:
        # Buscar tarefa
        task = db.query(ScheduledTask).filter(ScheduledTask.id == task_id).first()
        if not task:
            raise ValueError(f"Tarefa {task_id} não encontrada")
        
        # Criar execução
        execution = TaskService.create_task_execution(db, task_id, TaskStatus.RUNNING)
        
        # Executar baseado no tipo
        if task.task_type == "scan":
            server = db.query(Server).filter(Server.id == task.server_id).first()
            if server:
                path = task.parameters.get("path", "/")
                recursive = task.parameters.get("recursive", True)
                
                clamav = ClamAVService(
                    host=server.ip_address,
                    port=server.port,
                    socket_path=server.socket_path
                )
                
                results = await clamav.scan_directory(path, recursive)
                threats = [r for r in results if r["infected"]]
                
                output = f"Scan de {path} concluído\n"
                output += f"Ameaças encontradas: {len(threats)}"
                
                TaskService.update_task_execution(
                    db, execution.id, TaskStatus.COMPLETED, output
                )
        
        elif task.task_type == "update":
            # Atualizar assinaturas
            result = update_virus_signatures.delay()
            output = f"Atualização de assinaturas iniciada: {result.id}"
            
            TaskService.update_task_execution(
                db, execution.id, TaskStatus.COMPLETED, output
            )
        
        else:
            raise ValueError(f"Tipo de tarefa não suportado: {task.task_type}")
        
        # Atualizar próxima execução da tarefa
        task.last_run = datetime.utcnow()
        db.commit()
        
        return {"status": "completed", "task_type": task.task_type}
    
    except Exception as e:
        logger.error(f"Erro na execução da tarefa {task_id}: {e}")
        if execution:
            TaskService.update_task_execution(
                db, execution.id, TaskStatus.FAILED, error_message=str(e)
            )
        raise
    
    finally:
        db.close()
