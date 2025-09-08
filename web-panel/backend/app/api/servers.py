from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta

from app.core.database import get_db
from app.models.models import Server, ServerMetric, ScanResult, AuditLog
from app.schemas import (
    Server as ServerSchema, ServerCreate, ServerUpdate, ServerMetric as ServerMetricSchema,
    SystemMetrics, ApiResponse, ScanRequest
)
from app.api.auth import get_current_active_user, require_operator_or_admin
from app.services.clamav_service import ClamAVService, SystemMonitorService
from app.services.task_service import scan_directory_task
import asyncio
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/", response_model=List[ServerSchema])
async def list_servers(
    skip: int = 0,
    limit: int = 100,
    group: Optional[str] = None,
    status: Optional[str] = None,
    current_user = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Lista servidores com filtros opcionais"""
    
    query = db.query(Server)
    
    if group:
        query = query.filter(Server.group_name == group)
    
    if status:
        query = query.filter(Server.status == status)
    
    servers = query.offset(skip).limit(limit).all()
    return servers

@router.post("/", response_model=ServerSchema)
async def create_server(
    server_create: ServerCreate,
    background_tasks: BackgroundTasks,
    current_user = Depends(require_operator_or_admin),
    db: Session = Depends(get_db)
):
    """Cria novo servidor"""
    
    # Verificar se já existe servidor com mesmo hostname/IP
    existing = db.query(Server).filter(
        (Server.hostname == server_create.hostname) |
        (Server.ip_address == server_create.ip_address)
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Servidor com este hostname/IP já existe"
        )
    
    # Criar servidor
    server = Server(**server_create.dict())
    db.add(server)
    db.commit()
    db.refresh(server)
    
    # Testar conectividade em background
    background_tasks.add_task(test_server_connectivity, server.id)
    
    # Log de auditoria
    audit_log = AuditLog(
        user_id=current_user.id,
        action="create_server",
        resource="server",
        resource_id=str(server.id),
        details={"hostname": server.hostname, "ip_address": server.ip_address}
    )
    db.add(audit_log)
    db.commit()
    
    return server

@router.get("/{server_id}", response_model=ServerSchema)
async def get_server(
    server_id: int,
    current_user = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Obtém detalhes de um servidor"""
    
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Servidor não encontrado"
        )
    
    return server

@router.put("/{server_id}", response_model=ServerSchema)
async def update_server(
    server_id: int,
    server_update: ServerUpdate,
    current_user = Depends(require_operator_or_admin),
    db: Session = Depends(get_db)
):
    """Atualiza servidor"""
    
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Servidor não encontrado"
        )
    
    update_data = server_update.dict(exclude_unset=True)
    
    # Verificar duplicatas se hostname/IP mudaram
    if "hostname" in update_data or "ip_address" in update_data:
        query = db.query(Server).filter(Server.id != server_id)
        
        if "hostname" in update_data:
            query = query.filter(Server.hostname == update_data["hostname"])
        
        if "ip_address" in update_data:
            query = query.filter(Server.ip_address == update_data["ip_address"])
        
        if query.first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Servidor com este hostname/IP já existe"
            )
    
    # Atualizar campos
    for field, value in update_data.items():
        setattr(server, field, value)
    
    server.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(server)
    
    # Log de auditoria
    audit_log = AuditLog(
        user_id=current_user.id,
        action="update_server",
        resource="server",
        resource_id=str(server.id),
        details=update_data
    )
    db.add(audit_log)
    db.commit()
    
    return server

@router.delete("/{server_id}", response_model=ApiResponse)
async def delete_server(
    server_id: int,
    current_user = Depends(require_operator_or_admin),
    db: Session = Depends(get_db)
):
    """Remove servidor"""
    
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Servidor não encontrado"
        )
    
    # Verificar se há tarefas agendadas para este servidor
    from app.models.models import ScheduledTask
    active_tasks = db.query(ScheduledTask).filter(
        ScheduledTask.server_id == server_id,
        ScheduledTask.is_active == True
    ).count()
    
    if active_tasks > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Não é possível remover servidor com {active_tasks} tarefas ativas"
        )
    
    hostname = server.hostname
    db.delete(server)
    db.commit()
    
    # Log de auditoria
    audit_log = AuditLog(
        user_id=current_user.id,
        action="delete_server",
        resource="server",
        resource_id=str(server_id),
        details={"hostname": hostname}
    )
    db.add(audit_log)
    db.commit()
    
    return ApiResponse(success=True, message="Servidor removido com sucesso")

@router.post("/{server_id}/test-connection", response_model=ApiResponse)
async def test_server_connection(
    server_id: int,
    current_user = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Testa conectividade com servidor"""
    
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Servidor não encontrado"
        )
    
    try:
        clamav = ClamAVService(
            host=server.ip_address,
            port=server.port,
            socket_path=server.socket_path
        )
        
        is_online = await clamav.ping()
        
        if is_online:
            # Obter informações do ClamAV
            version_info = await clamav.get_version()
            stats = await clamav.get_stats()
            
            # Atualizar servidor
            server.status = "online"
            server.last_seen = datetime.utcnow()
            server.clamav_version = version_info.get("clamav_version")
            server.db_version = version_info.get("database_version")
            
            if "virus_database_entries" in stats:
                server.signatures_count = int(stats["virus_database_entries"])
            
            db.commit()
            
            return ApiResponse(
                success=True, 
                message="Servidor online", 
                data={
                    "status": "online",
                    "version_info": version_info,
                    "stats": stats
                }
            )
        else:
            server.status = "offline"
            db.commit()
            
            return ApiResponse(
                success=False, 
                message="Servidor offline"
            )
    
    except Exception as e:
        logger.error(f"Erro ao testar conexão com servidor {server_id}: {e}")
        server.status = "error"
        db.commit()
        
        return ApiResponse(
            success=False, 
            message=f"Erro de conexão: {str(e)}"
        )

@router.post("/{server_id}/scan", response_model=ApiResponse)
async def start_scan(
    server_id: int,
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user = Depends(require_operator_or_admin),
    db: Session = Depends(get_db)
):
    """Inicia scan em servidor específico"""
    
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Servidor não encontrado"
        )
    
    if server.status != "online":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Servidor deve estar online para executar scan"
        )
    
    # Iniciar tarefa de scan em background
    task = scan_directory_task.delay(
        server_id=server_id,
        directory_path=scan_request.path,
        recursive=scan_request.recursive
    )
    
    # Log de auditoria
    audit_log = AuditLog(
        user_id=current_user.id,
        action="start_scan",
        resource="server",
        resource_id=str(server_id),
        details={
            "path": scan_request.path,
            "recursive": scan_request.recursive,
            "task_id": task.id
        }
    )
    db.add(audit_log)
    db.commit()
    
    return ApiResponse(
        success=True,
        message="Scan iniciado",
        data={"task_id": task.id}
    )

@router.get("/{server_id}/metrics", response_model=List[ServerMetricSchema])
async def get_server_metrics(
    server_id: int,
    hours: int = 24,
    current_user = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Obtém métricas históricas do servidor"""
    
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Servidor não encontrado"
        )
    
    # Buscar métricas das últimas X horas
    since = datetime.utcnow() - timedelta(hours=hours)
    
    metrics = db.query(ServerMetric).filter(
        ServerMetric.server_id == server_id,
        ServerMetric.timestamp >= since
    ).order_by(ServerMetric.timestamp.desc()).all()
    
    return metrics

@router.get("/{server_id}/current-metrics", response_model=SystemMetrics)
async def get_current_server_metrics(
    server_id: int,
    current_user = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Obtém métricas atuais do servidor (apenas para localhost)"""
    
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Servidor não encontrado"
        )
    
    # Só funciona para servidores locais
    if server.ip_address not in ["localhost", "127.0.0.1"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Métricas só disponíveis para servidores locais"
        )
    
    try:
        metrics = SystemMonitorService.get_system_metrics()
        return SystemMetrics(**metrics)
    
    except Exception as e:
        logger.error(f"Erro ao obter métricas: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao obter métricas do sistema"
        )

@router.get("/{server_id}/scans", response_model=List)
async def get_server_scans(
    server_id: int,
    skip: int = 0,
    limit: int = 50,
    threats_only: bool = False,
    current_user = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Obtém histórico de scans do servidor"""
    
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Servidor não encontrado"
        )
    
    query = db.query(ScanResult).filter(ScanResult.server_id == server_id)
    
    if threats_only:
        query = query.filter(ScanResult.threat_found == True)
    
    scans = query.order_by(
        ScanResult.scan_date.desc()
    ).offset(skip).limit(limit).all()
    
    return scans

@router.post("/{server_id}/reload-database", response_model=ApiResponse)
async def reload_server_database(
    server_id: int,
    current_user = Depends(require_operator_or_admin),
    db: Session = Depends(get_db)
):
    """Recarrega banco de dados de assinaturas do servidor"""
    
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Servidor não encontrado"
        )
    
    if server.status != "online":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Servidor deve estar online"
        )
    
    try:
        clamav = ClamAVService(
            host=server.ip_address,
            port=server.port,
            socket_path=server.socket_path
        )
        
        success = await clamav.reload_database()
        
        if success:
            # Atualizar informações do servidor
            version_info = await clamav.get_version()
            stats = await clamav.get_stats()
            
            server.db_version = version_info.get("database_version")
            if "virus_database_entries" in stats:
                server.signatures_count = int(stats["virus_database_entries"])
            server.updated_at = datetime.utcnow()
            
            db.commit()
            
            # Log de auditoria
            audit_log = AuditLog(
                user_id=current_user.id,
                action="reload_database",
                resource="server",
                resource_id=str(server_id)
            )
            db.add(audit_log)
            db.commit()
            
            return ApiResponse(
                success=True,
                message="Banco de dados recarregado com sucesso"
            )
        else:
            return ApiResponse(
                success=False,
                message="Falha ao recarregar banco de dados"
            )
    
    except Exception as e:
        logger.error(f"Erro ao recarregar banco de dados: {e}")
        return ApiResponse(
            success=False,
            message=f"Erro: {str(e)}"
        )

# Função auxiliar para testar conectividade
async def test_server_connectivity(server_id: int):
    """Testa conectividade do servidor em background"""
    db = SessionLocal()
    
    try:
        server = db.query(Server).filter(Server.id == server_id).first()
        if not server:
            return
        
        clamav = ClamAVService(
            host=server.ip_address,
            port=server.port,
            socket_path=server.socket_path
        )
        
        is_online = await clamav.ping()
        
        if is_online:
            server.status = "online"
            server.last_seen = datetime.utcnow()
            
            # Obter informações adicionais
            try:
                version_info = await clamav.get_version()
                stats = await clamav.get_stats()
                
                server.clamav_version = version_info.get("clamav_version")
                server.db_version = version_info.get("database_version")
                
                if "virus_database_entries" in stats:
                    server.signatures_count = int(stats["virus_database_entries"])
                    
            except Exception as e:
                logger.warning(f"Erro ao obter informações do servidor {server_id}: {e}")
        else:
            server.status = "offline"
        
        db.commit()
        
    except Exception as e:
        logger.error(f"Erro ao testar conectividade do servidor {server_id}: {e}")
        if server:
            server.status = "error"
            db.commit()
    
    finally:
        db.close()
