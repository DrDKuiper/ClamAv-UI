from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.security import SecurityManager
from app.models.models import User, UserRole, AuditLog
from app.schemas import (
    User as UserSchema, UserCreate, UserUpdate, UserPasswordUpdate,
    Token, LoginRequest, Setup2FAResponse, Verify2FARequest, ApiResponse
)
from app.api.auth import get_current_user, get_current_active_user, require_admin

router = APIRouter()

@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Endpoint de login com suporte a 2FA"""
    
    # Buscar usuário
    user = db.query(User).filter(
        (User.username == form_data.username) | (User.email == form_data.username)
    ).first()
    
    if not user or not SecurityManager.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Conta desativada"
        )
    
    # Verificar 2FA se habilitado
    if user.is_2fa_enabled:
        if not form_data.client_secret:  # Usando client_secret para TOTP code
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Código 2FA obrigatório"
            )
        
        if not SecurityManager.verify_2fa_token(user.two_fa_secret, form_data.client_secret):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Código 2FA inválido"
            )
    
    # Atualizar último login
    user.last_login = datetime.utcnow()
    db.commit()
    
    # Criar tokens
    access_token = SecurityManager.create_access_token(subject=user.id)
    refresh_token = SecurityManager.create_refresh_token(subject=user.id)
    
    # Log de auditoria
    audit_log = AuditLog(
        user_id=user.id,
        action="login",
        resource="auth",
        details={"method": "password", "2fa_used": user.is_2fa_enabled}
    )
    db.add(audit_log)
    db.commit()
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_token: str,
    db: Session = Depends(get_db)
):
    """Renova token de acesso usando refresh token"""
    
    user_id = SecurityManager.verify_token(refresh_token)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token inválido"
        )
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário não encontrado ou inativo"
        )
    
    # Criar novo token de acesso
    access_token = SecurityManager.create_access_token(subject=user.id)
    new_refresh_token = SecurityManager.create_refresh_token(subject=user.id)
    
    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }

@router.get("/me", response_model=UserSchema)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user)
):
    """Obtém informações do usuário atual"""
    return current_user

@router.put("/me", response_model=UserSchema)
async def update_current_user(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Atualiza informações do usuário atual"""
    
    update_data = user_update.dict(exclude_unset=True)
    
    # Verificar se email/username já existem
    if "email" in update_data and update_data["email"] != current_user.email:
        if db.query(User).filter(User.email == update_data["email"]).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email já está em uso"
            )
    
    if "username" in update_data and update_data["username"] != current_user.username:
        if db.query(User).filter(User.username == update_data["username"]).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username já está em uso"
            )
    
    # Atualizar campos
    for field, value in update_data.items():
        if field != "role":  # Role só pode ser alterado por admin
            setattr(current_user, field, value)
    
    current_user.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(current_user)
    
    return current_user

@router.put("/me/password", response_model=ApiResponse)
async def change_password(
    password_update: UserPasswordUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Altera senha do usuário atual"""
    
    # Verificar senha atual
    if not SecurityManager.verify_password(
        password_update.current_password, 
        current_user.hashed_password
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Senha atual incorreta"
        )
    
    # Validar nova senha
    validation = SecurityManager.validate_password_strength(password_update.new_password)
    if not validation["valid"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Senha fraca: {', '.join(validation['errors'])}"
        )
    
    # Atualizar senha
    current_user.hashed_password = SecurityManager.get_password_hash(password_update.new_password)
    current_user.updated_at = datetime.utcnow()
    db.commit()
    
    # Log de auditoria
    audit_log = AuditLog(
        user_id=current_user.id,
        action="change_password",
        resource="user",
        resource_id=str(current_user.id)
    )
    db.add(audit_log)
    db.commit()
    
    return ApiResponse(success=True, message="Senha alterada com sucesso")

@router.post("/setup-2fa", response_model=Setup2FAResponse)
async def setup_2fa(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Configura autenticação de dois fatores"""
    
    if current_user.is_2fa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA já está habilitado"
        )
    
    # Gerar secret
    secret = SecurityManager.generate_2fa_secret()
    
    # Gerar QR code
    qr_code = SecurityManager.generate_2fa_qr_code(current_user.email, secret)
    
    # Gerar códigos de backup (não implementado aqui)
    backup_codes = []
    
    # Salvar secret temporariamente (será confirmado na verificação)
    current_user.two_fa_secret = secret
    db.commit()
    
    return Setup2FAResponse(
        secret=secret,
        qr_code=qr_code,
        backup_codes=backup_codes
    )

@router.post("/verify-2fa", response_model=ApiResponse)
async def verify_2fa(
    verify_request: Verify2FARequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Verifica e ativa 2FA"""
    
    if not SecurityManager.verify_2fa_token(verify_request.secret, verify_request.totp_code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código 2FA inválido"
        )
    
    # Ativar 2FA
    current_user.is_2fa_enabled = True
    current_user.two_fa_secret = verify_request.secret
    current_user.updated_at = datetime.utcnow()
    db.commit()
    
    # Log de auditoria
    audit_log = AuditLog(
        user_id=current_user.id,
        action="enable_2fa",
        resource="user",
        resource_id=str(current_user.id)
    )
    db.add(audit_log)
    db.commit()
    
    return ApiResponse(success=True, message="2FA ativado com sucesso")

@router.delete("/disable-2fa", response_model=ApiResponse)
async def disable_2fa(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Desativa autenticação de dois fatores"""
    
    if not current_user.is_2fa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA não está habilitado"
        )
    
    # Desativar 2FA
    current_user.is_2fa_enabled = False
    current_user.two_fa_secret = None
    current_user.updated_at = datetime.utcnow()
    db.commit()
    
    # Log de auditoria
    audit_log = AuditLog(
        user_id=current_user.id,
        action="disable_2fa",
        resource="user",
        resource_id=str(current_user.id)
    )
    db.add(audit_log)
    db.commit()
    
    return ApiResponse(success=True, message="2FA desativado com sucesso")

# Endpoints administrativos
@router.get("/users", response_model=List[UserSchema])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Lista todos os usuários (admin apenas)"""
    users = db.query(User).offset(skip).limit(limit).all()
    return users

@router.post("/users", response_model=UserSchema)
async def create_user(
    user_create: UserCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Cria novo usuário (admin apenas)"""
    
    # Verificar se email/username já existem
    if db.query(User).filter(User.email == user_create.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email já está em uso"
        )
    
    if db.query(User).filter(User.username == user_create.username).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username já está em uso"
        )
    
    # Validar senha
    validation = SecurityManager.validate_password_strength(user_create.password)
    if not validation["valid"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Senha fraca: {', '.join(validation['errors'])}"
        )
    
    # Criar usuário
    hashed_password = SecurityManager.get_password_hash(user_create.password)
    user_data = user_create.dict(exclude={"password"})
    
    new_user = User(**user_data, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Log de auditoria
    audit_log = AuditLog(
        user_id=current_user.id,
        action="create_user",
        resource="user",
        resource_id=str(new_user.id),
        details={"created_user": user_create.username}
    )
    db.add(audit_log)
    db.commit()
    
    return new_user

@router.put("/users/{user_id}", response_model=UserSchema)
async def update_user(
    user_id: int,
    user_update: UserUpdate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Atualiza usuário (admin apenas)"""
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    update_data = user_update.dict(exclude_unset=True)
    
    # Verificar duplicatas
    if "email" in update_data:
        existing = db.query(User).filter(
            User.email == update_data["email"],
            User.id != user_id
        ).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email já está em uso"
            )
    
    if "username" in update_data:
        existing = db.query(User).filter(
            User.username == update_data["username"],
            User.id != user_id
        ).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username já está em uso"
            )
    
    # Atualizar campos
    for field, value in update_data.items():
        setattr(user, field, value)
    
    user.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(user)
    
    return user

@router.delete("/users/{user_id}", response_model=ApiResponse)
async def delete_user(
    user_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Deleta usuário (admin apenas)"""
    
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Não é possível deletar sua própria conta"
        )
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    db.delete(user)
    db.commit()
    
    # Log de auditoria
    audit_log = AuditLog(
        user_id=current_user.id,
        action="delete_user",
        resource="user",
        resource_id=str(user_id),
        details={"deleted_user": user.username}
    )
    db.add(audit_log)
    db.commit()
    
    return ApiResponse(success=True, message="Usuário deletado com sucesso")
