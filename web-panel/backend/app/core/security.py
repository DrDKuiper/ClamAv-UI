from datetime import datetime, timedelta
from typing import Any, Union, Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from passlib.hash import bcrypt
from app.core.config import settings
import pyotp
import qrcode
import io
import base64

# Configuração de criptografia de senhas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class SecurityManager:
    """Gerenciador de segurança centralizado"""
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verifica se a senha fornecida corresponde ao hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def get_password_hash(password: str) -> str:
        """Gera hash da senha"""
        return pwd_context.hash(password)
    
    @staticmethod
    def create_access_token(
        subject: Union[str, Any], 
        expires_delta: timedelta = None
    ) -> str:
        """Cria token de acesso JWT"""
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )
        
        to_encode = {"exp": expire, "sub": str(subject), "type": "access"}
        encoded_jwt = jwt.encode(
            to_encode, 
            settings.JWT_SECRET_KEY, 
            algorithm=settings.ALGORITHM
        )
        return encoded_jwt
    
    @staticmethod
    def create_refresh_token(subject: Union[str, Any]) -> str:
        """Cria token de refresh"""
        expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        to_encode = {"exp": expire, "sub": str(subject), "type": "refresh"}
        encoded_jwt = jwt.encode(
            to_encode, 
            settings.JWT_SECRET_KEY, 
            algorithm=settings.ALGORITHM
        )
        return encoded_jwt
    
    @staticmethod
    def verify_token(token: str) -> Optional[str]:
        """Verifica e decodifica token JWT"""
        try:
            payload = jwt.decode(
                token, 
                settings.JWT_SECRET_KEY, 
                algorithms=[settings.ALGORITHM]
            )
            user_id: str = payload.get("sub")
            if user_id is None:
                return None
            return user_id
        except JWTError:
            return None
    
    @staticmethod
    def generate_2fa_secret() -> str:
        """Gera secret para 2FA"""
        return pyotp.random_base32()
    
    @staticmethod
    def generate_2fa_qr_code(user_email: str, secret: str) -> str:
        """Gera QR code para configuração 2FA"""
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_email,
            issuer_name=settings.APP_NAME
        )
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return base64.b64encode(buffer.getvalue()).decode()
    
    @staticmethod
    def verify_2fa_token(secret: str, token: str) -> bool:
        """Verifica token 2FA"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
    
    @staticmethod
    def validate_password_strength(password: str) -> dict:
        """Valida força da senha"""
        errors = []
        
        if len(password) < 8:
            errors.append("Senha deve ter pelo menos 8 caracteres")
        
        if not any(c.isupper() for c in password):
            errors.append("Senha deve conter pelo menos uma letra maiúscula")
        
        if not any(c.islower() for c in password):
            errors.append("Senha deve conter pelo menos uma letra minúscula")
        
        if not any(c.isdigit() for c in password):
            errors.append("Senha deve conter pelo menos um número")
        
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append("Senha deve conter pelo menos um caractere especial")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "strength": "weak" if len(errors) > 2 else "medium" if len(errors) > 0 else "strong"
        }
