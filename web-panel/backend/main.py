from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
import logging
import time
import uvicorn

from app.core.config import settings
from app.core.database import engine, Base
from app.api import users, servers
# from app.api import dashboard, quarantine, tasks, alerts, cve

# Configurar logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

# Criar tabelas do banco de dados
Base.metadata.create_all(bind=engine)

# Criar aplicação FastAPI
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Sistema de gerenciamento web para ClamAV",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)

# Middleware de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware de hosts confiáveis
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"] if settings.DEBUG else ["localhost", "127.0.0.1"]
)

# Middleware para logging de requests
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    
    # Log da request
    logger.info(f"Request: {request.method} {request.url}")
    
    response = await call_next(request)
    
    # Log da response
    process_time = time.time() - start_time
    logger.info(
        f"Response: {response.status_code} - {process_time:.3f}s"
    )
    
    return response

# Middleware para tratamento de erros
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "message": exc.detail,
            "status_code": exc.status_code
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Erro não tratado: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "message": "Erro interno do servidor",
            "status_code": 500
        }
    )

# Health check
@app.get("/health")
async def health_check():
    """Endpoint de verificação de saúde da aplicação"""
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "timestamp": time.time()
    }

# Rotas da API
app.include_router(
    users.router,
    prefix="/api/v1/auth",
    tags=["Autenticação"]
)

app.include_router(
    servers.router,
    prefix="/api/v1/servers",
    tags=["Servidores"]
)

# TODO: Adicionar outras rotas
# app.include_router(
#     dashboard.router,
#     prefix="/api/v1/dashboard",
#     tags=["Dashboard"]
# )

# app.include_router(
#     quarantine.router,
#     prefix="/api/v1/quarantine",
#     tags=["Quarentena"]
# )

# app.include_router(
#     tasks.router,
#     prefix="/api/v1/tasks",
#     tags=["Tarefas"]
# )

# app.include_router(
#     alerts.router,
#     prefix="/api/v1/alerts",
#     tags=["Alertas"]
# )

# app.include_router(
#     cve.router,
#     prefix="/api/v1/cve",
#     tags=["Vulnerabilidades"]
# )

# Documentação personalizada
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title=settings.APP_NAME,
        version=settings.VERSION,
        description="""
        ## Sistema de Gerenciamento Web para ClamAV
        
        Este sistema fornece uma interface web completa para gerenciamento de servidores ClamAV,
        incluindo monitoramento em tempo real, gerenciamento de quarentena, agendamento de tarefas
        e análise de vulnerabilidades CVE.
        
        ### Funcionalidades Principais
        
        - **Autenticação Segura**: Login com suporte a 2FA
        - **Gerenciamento de Servidores**: Adicionar, monitorar e gerenciar servidores ClamAV
        - **Monitoramento em Tempo Real**: Métricas de sistema e detecção de ameaças
        - **Quarentena**: Gerenciamento de arquivos em quarentena
        - **Tarefas Agendadas**: Automação de scans e atualizações
        - **Alertas**: Sistema de notificações em tempo real
        - **Análise CVE**: Integração com bases de vulnerabilidades
        
        ### Segurança
        
        - Autenticação JWT com refresh tokens
        - RBAC (Role-Based Access Control)
        - Comunicação criptografada (TLS/SSL)
        - Validação rigorosa de entrada
        - Auditoria completa de ações
        
        ### Como Usar
        
        1. Faça login usando suas credenciais
        2. Configure servidores ClamAV
        3. Monitore ameaças e métricas no dashboard
        4. Configure tarefas agendadas conforme necessário
        5. Gerencie arquivos em quarentena
        """,
        routes=app.routes,
    )
    
    # Adicionar informações de segurança
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }
    
    # Aplicar segurança a todas as rotas protegidas
    for path in openapi_schema["paths"]:
        for method in openapi_schema["paths"][path]:
            if method != "options":
                openapi_schema["paths"][path][method]["security"] = [
                    {"BearerAuth": []}
                ]
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

@app.get("/", include_in_schema=False)
async def root():
    """Endpoint raiz com informações da API"""
    return {
        "message": "ClamAV Web Panel API",
        "version": settings.VERSION,
        "docs": "/docs",
        "health": "/health"
    }

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )
