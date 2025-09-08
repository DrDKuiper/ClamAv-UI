# ClamAV Web Management Panel

Sistema completo de gerenciamento web para ClamAV com monitoramento em tempo real, gerenciamento de quarentena, análise de vulnerabilidades CVE e automação de tarefas.

## 📋 Funcionalidades

### 🔐 Segurança
- **Autenticação JWT** com refresh tokens
- **Autenticação de dois fatores (2FA)** com TOTP
- **RBAC** (Role-Based Access Control) com roles: Admin, Operator, Viewer
- **Comunicação criptografada** (TLS/SSL)
- **Auditoria completa** de todas as ações do sistema
- **Validação rigorosa** de entrada e sanitização de dados

### 🖥️ Gerenciamento de Servidores
- **Adicionar/remover servidores** ClamAV remotos
- **Monitoramento de status** em tempo real
- **Agrupamento de servidores** por categoria
- **Teste de conectividade** automático
- **Gerenciamento de configurações** remotas

### 📊 Dashboard e Monitoramento
- **Métricas em tempo real**: CPU, memória, disco, ameaças
- **Gráficos interativos** de tendências
- **Alertas configuráveis** por email
- **Status consolidado** de todos os servidores
- **Histórico de ameaças** e estatísticas

### 🛡️ Detecção e Quarentena
- **Escaneamento sob demanda** e agendado
- **Quarentena automática** de arquivos infectados
- **Gerenciamento de quarentena**: restaurar, deletar, analisar
- **Relatórios detalhados** de ameaças encontradas
- **Ações automáticas** configuráveis

### ⏰ Automação e Tarefas
- **Agendamento de tarefas** com cron expressions
- **Atualizações automáticas** de assinaturas
- **Limpeza automática** de quarentena
- **Execução de scripts** personalizados
- **Monitoramento de execução** de tarefas

### 🔍 Análise de Vulnerabilidades CVE
- **Integração com NVD** (National Vulnerability Database)
- **Busca automática** de vulnerabilidades
- **Análise de software** instalado
- **Priorização por criticidade** (CVSS)
- **Relatórios de vulnerabilidades**

### 📧 Sistema de Alertas
- **Notificações em tempo real** via WebSocket
- **Alertas por email** para eventos críticos
- **Categorização de alertas**: ameaças, sistema, servidores
- **Níveis de severidade**: baixo, médio, alto, crítico
- **Histórico e resolução** de alertas

## 🏗️ Arquitetura

### Tecnologias Utilizadas

**Backend:**
- **FastAPI** - Framework web moderno e rápido
- **SQLAlchemy** - ORM para Python
- **PostgreSQL** - Banco de dados principal
- **Redis** - Cache e filas de tarefas
- **Celery** - Processamento assíncrono
- **JWT** - Autenticação sem estado

**Frontend:** *(Implementação futura)*
- **React** - Interface de usuário
- **TypeScript** - Tipagem estática
- **Material-UI** - Componentes de interface
- **WebSockets** - Comunicação em tempo real

**Infraestrutura:**
- **Docker** - Containerização
- **Nginx** - Proxy reverso e load balancer
- **Alembic** - Migrations do banco de dados

### Componentes do Sistema

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     Frontend    │────│      Nginx      │────│     Backend     │
│   (React)       │    │  (Proxy/SSL)    │    │   (FastAPI)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
                       ┌─────────────────┐            │
                       │     Redis       │────────────┤
                       │  (Cache/Queue)  │            │
                       └─────────────────┘            │
                                                       │
                       ┌─────────────────┐            │
                       │   PostgreSQL    │────────────┘
                       │   (Database)    │
                       └─────────────────┘
                                │
                       ┌─────────────────┐
                       │     Celery      │
                       │   (Workers)     │
                       └─────────────────┘
```

## 🚀 Instalação e Configuração

### Pré-requisitos

- Docker e Docker Compose
- Git
- Pelo menos 4GB de RAM disponível
- 10GB de espaço em disco

### Instalação com Docker (Recomendado)

1. **Clone o repositório:**
```bash
git clone https://github.com/DrDKuiper/ClamAv-UI.git
cd ClamAv-UI/web-panel
```

2. **Configure as variáveis de ambiente:**
```bash
cp backend/.env.example backend/.env
# Edite o arquivo .env com suas configurações
```

3. **Inicie os serviços:**
```bash
docker-compose up -d
```

4. **Aguarde a inicialização (primeira vez pode demorar):**
```bash
docker-compose logs -f backend
```

5. **Acesse a aplicação:**
- Web Panel: http://localhost
- API Docs: http://localhost:8000/docs
- Flower (monitoring): http://localhost:5555

### Configuração Manual

#### 1. Backend

```bash
cd backend

# Criar ambiente virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows

# Instalar dependências
pip install -r requirements.txt

# Configurar banco de dados
cp .env.example .env
# Editar .env com suas configurações

# Executar migrations
alembic upgrade head

# Iniciar aplicação
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

#### 2. Serviços Auxiliares

**PostgreSQL:**
```bash
docker run -d --name clamav-postgres \
  -e POSTGRES_DB=clamav_ui \
  -e POSTGRES_USER=clamav_user \
  -e POSTGRES_PASSWORD=password \
  -p 5432:5432 \
  postgres:15
```

**Redis:**
```bash
docker run -d --name clamav-redis \
  -p 6379:6379 \
  redis:7-alpine
```

**Celery Worker:**
```bash
celery -A app.services.task_service worker --loglevel=info
```

**Celery Beat (scheduler):**
```bash
celery -A app.services.task_service beat --loglevel=info
```

## ⚙️ Configuração

### Variáveis de Ambiente

Principais configurações no arquivo `.env`:

```bash
# Segurança
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=jwt-secret-key-here
BCRYPT_ROUNDS=12

# Banco de Dados
DATABASE_URL=postgresql://user:password@localhost/clamav_ui
REDIS_URL=redis://localhost:6379

# ClamAV
CLAMD_HOST=localhost
CLAMD_PORT=3310
CLAMD_SOCKET=/var/run/clamav/clamd.ctl

# Email (Alertas)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL_RECIPIENTS=["admin@example.com"]

# CVE API
NVD_API_KEY=your-nvd-api-key

# Quarentena
QUARANTINE_PATH=/var/quarantine/clamav
MAX_QUARANTINE_SIZE_GB=10
```

### Primeiro Acesso

1. **Usuário padrão:**
   - Username: `admin`
   - Password: `admin123`

2. **Altere a senha imediatamente após o primeiro login**

3. **Configure servidores ClamAV:**
   - Vá para "Servidores" → "Adicionar Servidor"
   - Configure hostname, IP e porta
   - Teste a conectividade

## 📖 Uso da API

### Autenticação

```bash
# Login
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin123"

# Resposta
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer"
}
```

### Gerenciamento de Servidores

```bash
# Listar servidores
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8000/api/v1/servers/"

# Adicionar servidor
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Servidor Principal",
    "hostname": "server1.example.com",
    "ip_address": "192.168.1.100",
    "port": 3310,
    "group_name": "producao"
  }' \
  "http://localhost:8000/api/v1/servers/"

# Iniciar scan
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/home/user/documents",
    "recursive": true
  }' \
  "http://localhost:8000/api/v1/servers/1/scan"
```

## 🛠️ Desenvolvimento

### Estrutura do Projeto

```
web-panel/
├── backend/
│   ├── app/
│   │   ├── api/           # Endpoints da API
│   │   ├── core/          # Configurações centrais
│   │   ├── models/        # Modelos do banco de dados
│   │   ├── schemas.py     # Schemas Pydantic
│   │   └── services/      # Lógica de negócio
│   ├── alembic/           # Migrations
│   ├── docker/            # Configurações Docker
│   ├── tests/             # Testes unitários
│   └── main.py            # Aplicação principal
├── frontend/              # Interface React (futuro)
├── nginx/                 # Configurações Nginx
└── docker-compose.yml     # Orquestração
```

### Executar Testes

```bash
cd backend
pytest tests/ -v --cov=app
```

### Contribuição

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📊 Monitoramento e Logs

### Logs da Aplicação

```bash
# Ver logs em tempo real
docker-compose logs -f backend

# Ver logs específicos
docker-compose logs celery-worker
docker-compose logs postgres
```

### Métricas com Flower

Acesse http://localhost:5555 para monitorar:
- Tarefas Celery em execução
- Histórico de execução
- Estatísticas de workers
- Filas de tarefas

### Health Checks

```bash
# Status da aplicação
curl http://localhost:8000/health

# Status do banco de dados
docker-compose exec postgres pg_isready

# Status do Redis
docker-compose exec redis redis-cli ping
```

## 🔒 Segurança

### Práticas Implementadas

1. **Autenticação forte:**
   - JWT com expiração
   - 2FA opcional
   - Validação de força de senha

2. **Autorização:**
   - RBAC com roles granulares
   - Verificação de permissões por endpoint

3. **Comunicação:**
   - HTTPS obrigatório em produção
   - Validação de certificados
   - Headers de segurança

4. **Dados:**
   - Sanitização de entrada
   - Proteção contra SQL injection
   - Escape de XSS

5. **Auditoria:**
   - Log de todas as ações
   - Rastreamento de alterações
   - Alertas de segurança

### Configurações de Produção

```bash
# Gerar chaves seguras
openssl rand -base64 32  # SECRET_KEY
openssl rand -base64 32  # JWT_SECRET_KEY

# Configurar HTTPS
# Colocar certificados em nginx/ssl/
# Atualizar nginx.conf

# Configurar firewall
ufw allow 80
ufw allow 443
ufw deny 8000  # API apenas internamente
```

## 🚨 Troubleshooting

### Problemas Comuns

**1. Erro de conexão com banco:**
```bash
# Verificar status
docker-compose ps postgres

# Verificar logs
docker-compose logs postgres

# Resetar banco (CUIDADO!)
docker-compose down -v
docker-compose up -d postgres
```

**2. ClamAV não inicializa:**
```bash
# Verificar configuração
docker-compose exec backend cat /etc/clamav/clamd.conf

# Atualizar banco de vírus
docker-compose exec backend freshclam

# Restart serviço
docker-compose restart backend
```

**3. Tarefas Celery não executam:**
```bash
# Verificar workers
docker-compose logs celery-worker

# Verificar Redis
docker-compose exec redis redis-cli ping

# Limpar filas
docker-compose exec redis redis-cli flushall
```

### Logs de Debug

Para habilitar logs detalhados:

```bash
# No .env
DEBUG=true
LOG_LEVEL=DEBUG

# Restart
docker-compose restart backend
```

## 📞 Suporte

- **Issues:** https://github.com/DrDKuiper/ClamAv-UI/issues
- **Documentação:** https://github.com/DrDKuiper/ClamAv-UI/wiki
- **API Docs:** http://localhost:8000/docs

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 🙏 Agradecimentos

- Equipe do ClamAV pelo excelente antivírus
- Comunidade FastAPI
- Contribuidores do projeto

---

**Desenvolvido com ❤️ para melhorar a segurança de sistemas Linux**
