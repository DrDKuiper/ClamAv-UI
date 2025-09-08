from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, JSON, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
from enum import Enum

class UserRole(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"

class ServerStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"
    ERROR = "error"

class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String)
    role = Column(String, default=UserRole.VIEWER)
    is_active = Column(Boolean, default=True)
    is_2fa_enabled = Column(Boolean, default=False)
    two_fa_secret = Column(String)
    last_login = Column(DateTime)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relacionamentos
    audit_logs = relationship("AuditLog", back_populates="user")

class Server(Base):
    __tablename__ = "servers"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    hostname = Column(String, nullable=False)
    ip_address = Column(String, nullable=False)
    port = Column(Integer, default=3310)
    socket_path = Column(String)
    status = Column(String, default=ServerStatus.OFFLINE)
    last_seen = Column(DateTime)
    clamav_version = Column(String)
    db_version = Column(String)
    signatures_count = Column(Integer, default=0)
    group_name = Column(String)
    description = Column(Text)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relacionamentos
    scans = relationship("ScanResult", back_populates="server")
    metrics = relationship("ServerMetric", back_populates="server")
    tasks = relationship("ScheduledTask", back_populates="server")

class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("servers.id"))
    file_path = Column(String, nullable=False)
    file_size = Column(Integer)
    scan_time = Column(Float)  # tempo em segundos
    threat_found = Column(Boolean, default=False)
    threat_name = Column(String)
    threat_level = Column(String, default=ThreatLevel.LOW)
    action_taken = Column(String)  # quarantined, deleted, etc
    scan_date = Column(DateTime, default=func.now())
    
    # Relacionamentos
    server = relationship("Server", back_populates="scans")

class QuarantineItem(Base):
    __tablename__ = "quarantine_items"
    
    id = Column(Integer, primary_key=True, index=True)
    original_path = Column(String, nullable=False)
    quarantine_path = Column(String, nullable=False)
    file_size = Column(Integer)
    threat_name = Column(String, nullable=False)
    threat_level = Column(String, default=ThreatLevel.MEDIUM)
    server_hostname = Column(String, nullable=False)
    quarantined_at = Column(DateTime, default=func.now())
    is_restored = Column(Boolean, default=False)
    restored_at = Column(DateTime)
    notes = Column(Text)

class ScheduledTask(Base):
    __tablename__ = "scheduled_tasks"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    task_type = Column(String, nullable=False)  # scan, update, cleanup
    server_id = Column(Integer, ForeignKey("servers.id"))
    cron_expression = Column(String, nullable=False)
    parameters = Column(JSON)  # parâmetros específicos da tarefa
    status = Column(String, default=TaskStatus.PENDING)
    last_run = Column(DateTime)
    next_run = Column(DateTime)
    is_active = Column(Boolean, default=True)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=func.now())
    
    # Relacionamentos
    server = relationship("Server", back_populates="tasks")
    executions = relationship("TaskExecution", back_populates="task")

class TaskExecution(Base):
    __tablename__ = "task_executions"
    
    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(Integer, ForeignKey("scheduled_tasks.id"))
    status = Column(String, default=TaskStatus.PENDING)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    output = Column(Text)
    error_message = Column(Text)
    
    # Relacionamentos
    task = relationship("ScheduledTask", back_populates="executions")

class ServerMetric(Base):
    __tablename__ = "server_metrics"
    
    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("servers.id"))
    cpu_usage = Column(Float)
    memory_usage = Column(Float)
    disk_usage = Column(Float)
    scan_queue_size = Column(Integer, default=0)
    scans_per_hour = Column(Integer, default=0)
    threats_found = Column(Integer, default=0)
    timestamp = Column(DateTime, default=func.now())
    
    # Relacionamentos
    server = relationship("Server", back_populates="metrics")

class CVEVulnerability(Base):
    __tablename__ = "cve_vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, nullable=False)
    description = Column(Text)
    severity = Column(String)  # LOW, MEDIUM, HIGH, CRITICAL
    cvss_score = Column(Float)
    published_date = Column(DateTime)
    modified_date = Column(DateTime)
    affected_software = Column(JSON)  # lista de software afetado
    references = Column(JSON)  # links de referência
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    alert_type = Column(String, nullable=False)  # threat, system, update
    severity = Column(String, default=ThreatLevel.MEDIUM)
    server_hostname = Column(String)
    is_read = Column(Boolean, default=False)
    is_resolved = Column(Boolean, default=False)
    resolved_by = Column(Integer, ForeignKey("users.id"))
    resolved_at = Column(DateTime)
    created_at = Column(DateTime, default=func.now())
    
    # Metadados adicionais em JSON
    metadata = Column(JSON)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String, nullable=False)
    resource = Column(String)  # que recurso foi afetado
    resource_id = Column(String)  # ID do recurso
    details = Column(JSON)  # detalhes da ação
    ip_address = Column(String)
    user_agent = Column(String)
    timestamp = Column(DateTime, default=func.now())
    
    # Relacionamentos
    user = relationship("User", back_populates="audit_logs")

class SystemConfig(Base):
    __tablename__ = "system_config"
    
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, nullable=False)
    value = Column(String, nullable=False)
    description = Column(Text)
    category = Column(String)  # security, monitoring, alerts, etc
    is_sensitive = Column(Boolean, default=False)  # se contém informação sensível
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
