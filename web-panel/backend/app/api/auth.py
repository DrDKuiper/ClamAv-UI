from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import SecurityManager
from app.models.models import User, UserRole
from typing import Optional
import logging

logger = logging.getLogger(__name__)

security = HTTPBearer()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """Obtém o usuário atual baseado no token JWT"""
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não foi possível validar as credenciais",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        token = credentials.credentials
        user_id = SecurityManager.verify_token(token)
        
        if user_id is None:
            raise credentials_exception
        
        user = db.query(User).filter(User.id == user_id).first()
        
        if user is None:
            raise credentials_exception
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuário inativo"
            )
        
        return user
    
    except Exception as e:
        logger.error(f"Erro na autenticação: {e}")
        raise credentials_exception

async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Obtém usuário ativo"""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuário inativo"
        )
    return current_user

def require_role(required_roles: list):
    """Decorator para exigir roles específicas"""
    def role_checker(current_user: User = Depends(get_current_active_user)):
        if current_user.role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permissões insuficientes"
            )
        return current_user
    return role_checker

# Dependências específicas para cada role
async def require_admin(current_user: User = Depends(get_current_active_user)) -> User:
    """Requer role de administrador"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso restrito a administradores"
        )
    return current_user

async def require_operator_or_admin(current_user: User = Depends(get_current_active_user)) -> User:
    """Requer role de operador ou administrador"""
    if current_user.role not in [UserRole.ADMIN, UserRole.OPERATOR]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso restrito a operadores e administradores"
        )
    return current_user

async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Obtém usuário se autenticado, caso contrário retorna None"""
    if not credentials:
        return None
    
    try:
        token = credentials.credentials
        user_id = SecurityManager.verify_token(token)
        
        if user_id is None:
            return None
        
        user = db.query(User).filter(User.id == user_id).first()
        
        if user is None or not user.is_active:
            return None
        
        return user
    
    except Exception:
        return None
