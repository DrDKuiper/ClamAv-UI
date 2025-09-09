#!/bin/bash

# Script de Instalação Automatizada - ClamAV Web Panel
# Versão: 1.0.0
# Autor: Sistema de Gerenciamento ClamAV

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funções auxiliares
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Função para executar comandos com ou sem sudo conforme necessário
run_command() {
    if [[ $EUID -ne 0 ]]; then
        # Não é root, tenta com sudo primeiro
        if command -v sudo &> /dev/null; then
            sudo "$@"
        else
            # sudo não existe, tenta sem sudo
            "$@"
        fi
    else
        # É root, executa diretamente
        "$@"
    fi
}

check_prerequisites() {
    log_info "Verificando pré-requisitos..."
    
    # Detectar gerenciador de pacotes (suporta apt e yum/dnf)
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt-get"
        INSTALL_CMD="apt-get install -y"
        UPDATE_CMD="apt-get update"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        INSTALL_CMD="dnf install -y"
        UPDATE_CMD="" # dnf atualiza automaticamente
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        INSTALL_CMD="yum install -y"
        UPDATE_CMD=""
    else
        log_error "Gerenciador de pacotes não suportado. Instale Docker, Docker Compose e Git manualmente."
        exit 1
    fi

    # Garantir que os comandos básicos estejam disponíveis
    if ! command -v curl &> /dev/null; then
        log_info "Instalando curl..."
        if [ -n "$UPDATE_CMD" ]; then
            run_command $UPDATE_CMD
        fi
        run_command $INSTALL_CMD curl
    fi

    # Verificar Docker
    if ! command -v docker &> /dev/null; then
        # Cenário Docker-out-of-Docker (DooD): socket existe, mas o cliente não.
        if [ -S /var/run/docker.sock ]; then
            log_warning "Docker socket detectado, mas o cliente Docker não. Instalando docker-ce-cli..."
            if [ "$PKG_MANAGER" = "apt-get" ]; then
                # Instala dependências para adicionar o repo do Docker
                run_command apt-get install -y ca-certificates
                # Adiciona o repositório oficial do Docker
                run_command install -m 0755 -d /etc/apt/keyrings
                curl -fsSL https://download.docker.com/linux/ubuntu/gpg | run_command gpg --dearmor -o /etc/apt/keyrings/docker.gpg
                run_command chmod a+r /etc/apt/keyrings/docker.gpg
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | run_command tee /etc/apt/sources.list.d/docker.list > /dev/null
                run_command apt-get update
                # Instala apenas o cliente
                run_command apt-get install -y docker-ce-cli
                log_success "Cliente Docker (docker-ce-cli) instalado com sucesso."
            else
                log_error "A instalação automática do docker-ce-cli para ${PKG_MANAGER} não é suportada. Instale manualmente."
                exit 1
            fi
        # Cenário normal: Docker não está instalado
        else
            log_error "Docker não encontrado. Instalando Docker via script oficial..."
            curl -fsSL https://get.docker.com -o get-docker.sh
            sh get-docker.sh
            run_command usermod -aG docker $USER
            log_success "Docker instalado com sucesso. Pode ser necessário reiniciar o terminal ou fazer logout/login."
        fi
    else
        log_success "Docker encontrado: $(docker --version)"
    fi
    
    # Verificar Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose não encontrado. Instalando..."
        run_command curl -L "https://github.com/docker/compose/releases/download/v2.21.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        run_command chmod +x /usr/local/bin/docker-compose
        log_success "Docker Compose instalado com sucesso"
    else
        log_success "Docker Compose encontrado: $(docker-compose --version)"
    fi
    
    # Verificar Git
    if ! command -v git &> /dev/null; then
        log_error "Git não encontrado. Instalando Git..."
        run_command $INSTALL_CMD git
        log_success "Git instalado com sucesso"
    else
        log_success "Git encontrado: $(git --version)"
    fi
    
    # Verificar recursos do sistema
    log_info "Verificando recursos do sistema..."
    
    # RAM disponível
    if command -v free &> /dev/null; then
        RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
        if [ $RAM_GB -lt 4 ]; then
            log_warning "RAM disponível: ${RAM_GB}GB (recomendado: 4GB+)"
        else
            log_success "RAM disponível: ${RAM_GB}GB"
        fi
    fi
    
    # Espaço em disco
    DISK_GB=$(df -BG / | awk 'NR==2{print $4}' | sed 's/G//')
    if [ $DISK_GB -lt 10 ]; then
        log_warning "Espaço em disco: ${DISK_GB}GB (recomendado: 10GB+)"
    else
        log_success "Espaço em disco: ${DISK_GB}GB"
    fi
}

clone_repository() {
    log_info "Clonando repositório..."
    
    if [ -d "ClamAv-UI" ]; then
        log_warning "Diretório ClamAv-UI já existe. Removendo..."
        rm -rf ClamAv-UI
    fi
    
    git clone https://github.com/DrDKuiper/ClamAv-UI.git
    cd ClamAv-UI/web-panel
    
    log_success "Repositório clonado com sucesso"
}

configure_environment() {
    log_info "Configurando ambiente..."
    
    # Gerar chaves seguras
    SECRET_KEY=$(openssl rand -base64 32)
    JWT_SECRET_KEY=$(openssl rand -base64 32)
    DB_PASSWORD=$(openssl rand -base64 16)
    REDIS_PASSWORD=$(openssl rand -base64 16)
    
    # Criar arquivo .env
    cat > backend/.env << EOF
# Configurações de Segurança
SECRET_KEY=${SECRET_KEY}
JWT_SECRET_KEY=${JWT_SECRET_KEY}
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
ALGORITHM=HS256
BCRYPT_ROUNDS=12

# Banco de Dados
DATABASE_URL=postgresql://clamav_user:${DB_PASSWORD}@postgres:5432/clamav_ui
REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379

# ClamAV Configuration
CLAMD_HOST=localhost
CLAMD_PORT=3310
CLAMD_SOCKET=/var/run/clamav/clamd.ctl

# Email Configuration (Configure conforme necessário)
SMTP_HOST=localhost
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_TLS=True

# CVE API (Opcional - obtenha em https://nvd.nist.gov/developers/request-an-api-key)
NVD_API_KEY=

# Aplicação
DEBUG=False
LOG_LEVEL=INFO
CORS_ORIGINS=["http://localhost:3000", "http://localhost", "https://localhost"]

# Quarentena
QUARANTINE_PATH=/var/quarantine/clamav
MAX_QUARANTINE_SIZE_GB=10

# Monitoramento
METRICS_RETENTION_DAYS=30
ALERT_EMAIL_RECIPIENTS=["admin@example.com"]
EOF

    # Atualizar docker-compose.yml com senhas geradas
    # Usar | como delimitador para evitar problemas com caracteres especiais
    sed -i "s|secure_password_123|${DB_PASSWORD}|g" docker-compose.yml
    sed -i "s|redis_password_123|${REDIS_PASSWORD}|g" docker-compose.yml
    sed -i "s|your-super-secret-key-change-in-production|${SECRET_KEY}|g" docker-compose.yml
    sed -i "s|jwt-super-secret-key-change-in-production|${JWT_SECRET_KEY}|g" docker-compose.yml
    
    log_success "Ambiente configurado com chaves seguras geradas"
    
    # Salvar credenciais
    cat > credentials.txt << EOF
=== CREDENCIAIS DO SISTEMA ===
Data de Instalação: $(date)

Banco de Dados:
- Usuário: clamav_user
- Senha: ${DB_PASSWORD}
- Database: clamav_ui

Redis:
- Senha: ${REDIS_PASSWORD}

Usuário Administrador Padrão:
- Username: admin
- Password: admin123
- IMPORTANTE: Altere a senha após o primeiro login!

Chaves de Segurança:
- SECRET_KEY: ${SECRET_KEY}
- JWT_SECRET_KEY: ${JWT_SECRET_KEY}

MANTENHA ESTE ARQUIVO SEGURO!
EOF
    
    chmod 600 credentials.txt
    log_warning "Credenciais salvas em credentials.txt - MANTENHA SEGURO!"
}

setup_ssl() {
    log_info "Configurando SSL/TLS..."
    
    mkdir -p nginx/ssl
    
    # Gerar certificado auto-assinado para desenvolvimento
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout nginx/ssl/clamav.key \
        -out nginx/ssl/clamav.crt \
        -subj "/C=BR/ST=SP/L=SaoPaulo/O=ClamAV/CN=localhost"
    
    log_warning "Certificado SSL auto-assinado criado para desenvolvimento"
    log_warning "Para produção, use certificados válidos (Let's Encrypt, etc.)"
}

create_nginx_config() {
    log_info "Criando configuração Nginx..."
    
    mkdir -p nginx
    
    cat > nginx/nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    upstream backend {
        server backend:8000;
    }
    
    upstream frontend {
        server frontend:80;
    }
    
    # Redirect HTTP to HTTPS
    server {
        listen 80;
        server_name _;
        return 301 https://$server_name$request_uri;
    }
    
    # HTTPS Server
    server {
        listen 443 ssl http2;
        server_name _;
        
        ssl_certificate /etc/nginx/ssl/clamav.crt;
        ssl_certificate_key /etc/nginx/ssl/clamav.key;
        
        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "no-referrer-when-downgrade" always;
        add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
        
        # API routes
        location /api/ {
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
        
        # Health check
        location /health {
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
        
        # Documentation
        location /docs {
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
        
        # Frontend
        location / {
            proxy_pass http://frontend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
EOF
    
    log_success "Configuração Nginx criada"
}

start_services() {
    log_info "Iniciando serviços..."
    
    # Criar volumes necessários
    docker volume create clamav_postgres_data
    docker volume create clamav_redis_data
    docker volume create clamav_quarantine_data
    docker volume create clamav_virus_db
    docker volume create clamav_logs
    
    # Iniciar serviços
    docker-compose up -d
    
    log_info "Aguardando inicialização dos serviços..."
    sleep 30
    
    # Verificar status dos serviços
    log_info "Verificando status dos serviços..."
    docker-compose ps
    
    # Aguardar backend estar pronto
    log_info "Aguardando backend estar pronto..."
    timeout 300 bash -c 'until curl -s http://localhost:8000/health; do sleep 5; done'
    
    log_success "Serviços iniciados com sucesso!"
}

run_initial_setup() {
    log_info "Executando configuração inicial..."
    
    # Executar migrations
    docker-compose exec -T backend alembic upgrade head
    
    # Criar usuário admin
    log_info "Criando usuário administrador padrão..."
    docker-compose exec -T backend python -c "from app.core.database import get_db; from app.models.user import User; from app.services.user_service import UserService; db = next(get_db()); user_service = UserService(db); user_service.create_initial_user()"
    
    log_success "Configuração inicial concluída"
}

show_access_info() {
    log_success "=== INSTALAÇÃO CONCLUÍDA COM SUCESSO! ==="
    echo
    log_info "Acesso ao sistema:"
    echo "  🌐 Web Panel: https://localhost"
    echo "  📚 API Docs:  https://localhost/docs"
    echo "  🔍 Flower:    http://localhost:5555 (monitoramento)"
    echo
    log_info "Credenciais padrão:"
    echo "  👤 Username: admin"
    echo "  🔑 Password: admin123"
    echo
    log_warning "IMPORTANTE:"
    echo "  ⚠️  Altere a senha padrão após o primeiro login"
    echo "  ⚠️  Configure seu servidor SMTP para alertas por email"
    echo "  ⚠️  Obtenha uma chave da API NVD para análise CVE"
    echo "  ⚠️  Em produção, use certificados SSL válidos"
    echo
    log_info "Comandos úteis:"
    echo "  🔄 Reiniciar:     docker-compose restart"
    echo "  📋 Ver logs:      docker-compose logs -f"
    echo "  ⏹️  Parar:         docker-compose stop"
    echo "  🗑️  Remover tudo:  docker-compose down -v"
    echo
    log_info "Arquivos importantes:"
    echo "  📄 Credenciais:   ./credentials.txt"
    echo "  ⚙️  Configuração:  ./backend/.env"
    echo "  🐳 Compose:       ./docker-compose.yml"
    echo
    log_success "Sistema pronto para uso! 🚀"
}

cleanup_on_error() {
    log_error "Erro durante a instalação. Limpando..."
    docker-compose down -v 2>/dev/null || true
    exit 1
}

# Função principal
main() {
    echo "================================================"
    echo "    ClamAV Web Panel - Instalação Automática    "
    echo "================================================"
    echo
    
    # Trap para limpeza em caso de erro
    trap cleanup_on_error ERR

    # Menu de confirmação
    log_warning "Este script irá:"
    echo "  ✓ Verificar e instalar pré-requisitos (Docker, Docker Compose, Git)"
    echo "  ✓ Clonar o repositório ClamAV Web Panel"
    echo "  ✓ Configurar ambiente com chaves seguras"
    echo "  ✓ Criar certificados SSL para desenvolvimento"
    echo "  ✓ Iniciar todos os serviços via Docker Compose"
    echo "  ✓ Executar configuração inicial do banco de dados"
    echo
    read -p "Deseja continuar? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Instalação cancelada pelo usuário"
        exit 0
    fi
    
    # Executar instalação
    check_prerequisites
    clone_repository
    configure_environment
    setup_ssl
    create_nginx_config
    start_services
    run_initial_setup
    show_access_info
}

# Executar função principal
main "$@"
