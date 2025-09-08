from pydantic import BaseModel, EmailStr, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

# Enums para validação
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

# Schemas de Usuário
class UserBase(BaseModel):
    email: EmailStr
    username: str
    full_name: Optional[str] = None
    role: UserRole = UserRole.VIEWER
    is_active: bool = True

class UserCreate(UserBase):
    password: str
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Senha deve ter pelo menos 8 caracteres')
        return v

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    username: Optional[str] = None
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None

class User(UserBase):
    id: int
    is_2fa_enabled: bool
    last_login: Optional[datetime]
    created_at: datetime
    
    class Config:
        from_attributes = True

class UserLogin(BaseModel):
    username: str
    password: str
    totp_code: Optional[str] = None

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class TwoFactorSetup(BaseModel):
    secret: str
    qr_code: str

# Schemas de Servidor
class ServerBase(BaseModel):
    name: str
    hostname: str
    ip_address: str
    port: int = 3310
    socket_path: Optional[str] = None
    group_name: Optional[str] = None
    description: Optional[str] = None

class ServerCreate(ServerBase):
    pass

class ServerUpdate(BaseModel):
    name: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None
    socket_path: Optional[str] = None
    group_name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[ServerStatus] = None

class Server(ServerBase):
    id: int
    status: ServerStatus
    last_seen: Optional[datetime]
    clamav_version: Optional[str]
    db_version: Optional[str]
    signatures_count: int
    created_at: datetime
    
    class Config:
        from_attributes = True

# Schemas de Scan
class ScanResultBase(BaseModel):
    file_path: str
    file_size: Optional[int] = None
    scan_time: Optional[float] = None
    threat_found: bool = False
    threat_name: Optional[str] = None
    threat_level: ThreatLevel = ThreatLevel.LOW
    action_taken: Optional[str] = None

class ScanResultCreate(ScanResultBase):
    server_id: int

class ScanResult(ScanResultBase):
    id: int
    server_id: int
    scan_date: datetime
    
    class Config:
        from_attributes = True

# Schemas de Quarentena
class QuarantineItemBase(BaseModel):
    original_path: str
    file_size: Optional[int] = None
    threat_name: str
    threat_level: ThreatLevel = ThreatLevel.MEDIUM
    server_hostname: str
    notes: Optional[str] = None

class QuarantineItemCreate(QuarantineItemBase):
    quarantine_path: str

class QuarantineItem(QuarantineItemBase):
    id: int
    quarantine_path: str
    quarantined_at: datetime
    is_restored: bool
    restored_at: Optional[datetime]
    
    class Config:
        from_attributes = True

# Schemas de Tarefas Agendadas
class ScheduledTaskBase(BaseModel):
    name: str
    task_type: str
    cron_expression: str
    parameters: Optional[Dict[str, Any]] = None
    is_active: bool = True

class ScheduledTaskCreate(ScheduledTaskBase):
    server_id: int

class ScheduledTaskUpdate(BaseModel):
    name: Optional[str] = None
    cron_expression: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None

class ScheduledTask(ScheduledTaskBase):
    id: int
    server_id: int
    status: TaskStatus
    last_run: Optional[datetime]
    next_run: Optional[datetime]
    created_by: int
    created_at: datetime
    
    class Config:
        from_attributes = True

# Schemas de Métricas
class ServerMetricBase(BaseModel):
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    disk_usage: Optional[float] = None
    scan_queue_size: int = 0
    scans_per_hour: int = 0
    threats_found: int = 0

class ServerMetricCreate(ServerMetricBase):
    server_id: int

class ServerMetric(ServerMetricBase):
    id: int
    server_id: int
    timestamp: datetime
    
    class Config:
        from_attributes = True

# Schemas de CVE
class CVEVulnerabilityBase(BaseModel):
    cve_id: str
    description: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    published_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    affected_software: Optional[List[str]] = None
    references: Optional[List[str]] = None

class CVEVulnerabilityCreate(CVEVulnerabilityBase):
    pass

class CVEVulnerability(CVEVulnerabilityBase):
    id: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

# Schemas de Alertas
class AlertBase(BaseModel):
    title: str
    message: str
    alert_type: str
    severity: ThreatLevel = ThreatLevel.MEDIUM
    server_hostname: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class AlertCreate(AlertBase):
    pass

class AlertUpdate(BaseModel):
    is_read: Optional[bool] = None
    is_resolved: Optional[bool] = None

class Alert(AlertBase):
    id: int
    is_read: bool
    is_resolved: bool
    resolved_by: Optional[int]
    resolved_at: Optional[datetime]
    created_at: datetime
    
    class Config:
        from_attributes = True

# Schemas de Dashboard
class DashboardStats(BaseModel):
    total_servers: int
    online_servers: int
    offline_servers: int
    total_threats_today: int
    total_scans_today: int
    quarantine_items: int
    active_alerts: int
    recent_threats: List[ScanResult]
    server_status_distribution: Dict[str, int]

class ServerHealthStatus(BaseModel):
    server: Server
    current_metrics: Optional[ServerMetric]
    last_scan_count: int
    threat_count_24h: int
    is_healthy: bool
    issues: List[str]

# Schemas de Configuração
class SystemConfigBase(BaseModel):
    key: str
    value: str
    description: Optional[str] = None
    category: Optional[str] = None

class SystemConfigCreate(SystemConfigBase):
    pass

class SystemConfigUpdate(BaseModel):
    value: str
    description: Optional[str] = None

class SystemConfig(SystemConfigBase):
    id: int
    is_sensitive: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

# Schemas de resposta para APIs
class MessageResponse(BaseModel):
    message: str
    success: bool = True

class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    per_page: int
    pages: int

# Schema para scan manual
class ManualScanRequest(BaseModel):
    server_id: int
    path: str
    recursive: bool = True
    follow_symlinks: bool = False
