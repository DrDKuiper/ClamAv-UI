from pydantic import BaseModel, EmailStr, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

# Enums para validação
class UserRoleEnum(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"

class ServerStatusEnum(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"
    ERROR = "error"

class ThreatLevelEnum(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class TaskStatusEnum(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

# Schemas de usuário
class UserBase(BaseModel):
    email: EmailStr
    username: str
    full_name: Optional[str] = None
    role: UserRoleEnum = UserRoleEnum.VIEWER

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
    role: Optional[UserRoleEnum] = None
    is_active: Optional[bool] = None

class UserPasswordUpdate(BaseModel):
    current_password: str
    new_password: str
    
    @validator('new_password')
    def validate_new_password(cls, v):
        if len(v) < 8:
            raise ValueError('Nova senha deve ter pelo menos 8 caracteres')
        return v

class User(UserBase):
    id: int
    is_active: bool
    is_2fa_enabled: bool
    last_login: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

# Schemas de autenticação
class TokenData(BaseModel):
    username: Optional[str] = None

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: Optional[str] = None

class Setup2FAResponse(BaseModel):
    secret: str
    qr_code: str
    backup_codes: List[str]

class Verify2FARequest(BaseModel):
    secret: str
    totp_code: str

# Schemas de servidor
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
    status: Optional[ServerStatusEnum] = None

class Server(ServerBase):
    id: int
    status: ServerStatusEnum
    last_seen: Optional[datetime]
    clamav_version: Optional[str]
    db_version: Optional[str]
    signatures_count: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

# Schemas de scan
class ScanRequest(BaseModel):
    path: str
    recursive: bool = True
    server_id: Optional[int] = None

class ScanResult(BaseModel):
    id: int
    server_id: int
    file_path: str
    file_size: Optional[int]
    scan_time: Optional[float]
    threat_found: bool
    threat_name: Optional[str]
    threat_level: ThreatLevelEnum
    action_taken: Optional[str]
    scan_date: datetime
    
    class Config:
        from_attributes = True

# Schemas de quarentena
class QuarantineItemBase(BaseModel):
    original_path: str
    threat_name: str
    threat_level: ThreatLevelEnum = ThreatLevelEnum.MEDIUM
    server_hostname: str
    notes: Optional[str] = None

class QuarantineItemCreate(QuarantineItemBase):
    quarantine_path: str
    file_size: Optional[int] = None

class QuarantineItem(QuarantineItemBase):
    id: int
    quarantine_path: str
    file_size: Optional[int]
    quarantined_at: datetime
    is_restored: bool
    restored_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class QuarantineAction(BaseModel):
    action: str  # restore, delete
    notes: Optional[str] = None

# Schemas de tarefas agendadas
class ScheduledTaskBase(BaseModel):
    name: str
    task_type: str
    server_id: Optional[int] = None
    cron_expression: str
    parameters: Optional[Dict[str, Any]] = {}
    is_active: bool = True

class ScheduledTaskCreate(ScheduledTaskBase):
    pass

class ScheduledTaskUpdate(BaseModel):
    name: Optional[str] = None
    cron_expression: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None

class ScheduledTask(ScheduledTaskBase):
    id: int
    status: TaskStatusEnum
    last_run: Optional[datetime]
    next_run: Optional[datetime]
    created_by: Optional[int]
    created_at: datetime
    
    class Config:
        from_attributes = True

class TaskExecution(BaseModel):
    id: int
    task_id: int
    status: TaskStatusEnum
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    output: Optional[str]
    error_message: Optional[str]
    
    class Config:
        from_attributes = True

# Schemas de métricas
class ServerMetric(BaseModel):
    id: int
    server_id: int
    cpu_usage: Optional[float]
    memory_usage: Optional[float]
    disk_usage: Optional[float]
    scan_queue_size: int
    scans_per_hour: int
    threats_found: int
    timestamp: datetime
    
    class Config:
        from_attributes = True

class SystemMetrics(BaseModel):
    cpu_usage: float
    memory_usage: float
    memory_total: int
    memory_available: int
    disk_usage: float
    disk_total: int
    disk_free: int
    load_average: List[float]
    uptime: float
    timestamp: datetime

# Schemas de alertas
class AlertBase(BaseModel):
    title: str
    message: str
    alert_type: str
    severity: ThreatLevelEnum = ThreatLevelEnum.MEDIUM
    server_hostname: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = {}

class AlertCreate(AlertBase):
    pass

class Alert(AlertBase):
    id: int
    is_read: bool
    is_resolved: bool
    resolved_by: Optional[int]
    resolved_at: Optional[datetime]
    created_at: datetime
    
    class Config:
        from_attributes = True

class AlertAction(BaseModel):
    action: str  # read, resolve
    notes: Optional[str] = None

# Schemas de CVE
class CVEVulnerability(BaseModel):
    id: int
    cve_id: str
    description: Optional[str]
    severity: str
    cvss_score: Optional[float]
    published_date: Optional[datetime]
    modified_date: Optional[datetime]
    affected_software: Optional[List[str]]
    references: Optional[List[str]]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class CVESearchRequest(BaseModel):
    keyword: Optional[str] = None
    software: Optional[str] = None
    severity: Optional[List[str]] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    limit: int = 20

# Schemas de dashboard
class DashboardStats(BaseModel):
    total_servers: int
    online_servers: int
    offline_servers: int
    total_threats_24h: int
    active_alerts: int
    quarantine_items: int
    last_update: datetime

class ThreatTrend(BaseModel):
    date: str
    threat_count: int
    critical_threats: int

class ServerHealth(BaseModel):
    server_id: int
    server_name: str
    hostname: str
    status: ServerStatusEnum
    cpu_usage: Optional[float]
    memory_usage: Optional[float]
    threats_today: int
    last_seen: Optional[datetime]

# Schemas de resposta de API
class ApiResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Any] = None

class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    size: int
    pages: int

# Schemas de configuração
class SystemConfigUpdate(BaseModel):
    key: str
    value: str
    description: Optional[str] = None
    category: Optional[str] = None
