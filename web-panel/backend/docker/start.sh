#!/bin/bash

# Script de inicialização do container

echo "Iniciando ClamAV Web Panel..."

# Aguardar banco de dados estar disponível
echo "Aguardando banco de dados..."
python -c "
import time
import psycopg2
from app.core.config import settings

max_attempts = 30
attempt = 0

while attempt < max_attempts:
    try:
        conn = psycopg2.connect(settings.DATABASE_URL)
        conn.close()
        print('Banco de dados disponível!')
        break
    except psycopg2.OperationalError:
        print(f'Tentativa {attempt + 1}/{max_attempts} - Aguardando banco...')
        time.sleep(2)
        attempt += 1

if attempt == max_attempts:
    print('Erro: Não foi possível conectar ao banco de dados')
    exit(1)
"

# Executar migrations
echo "Executando migrations do banco de dados..."
alembic upgrade head

# Criar usuário administrador padrão se não existir
echo "Verificando usuário administrador..."
python -c "
from app.core.database import SessionLocal
from app.models.models import User
from app.core.security import SecurityManager

db = SessionLocal()
admin_user = db.query(User).filter(User.username == 'admin').first()

if not admin_user:
    print('Criando usuário administrador padrão...')
    admin = User(
        username='admin',
        email='admin@example.com',
        full_name='Administrador',
        role='admin',
        hashed_password=SecurityManager.get_password_hash('admin123')
    )
    db.add(admin)
    db.commit()
    print('Usuário admin criado com senha: admin123')
    print('IMPORTANTE: Altere a senha padrão após o primeiro login!')
else:
    print('Usuário administrador já existe.')

db.close()
"

# Inicializar ClamAV se necessário
if [ ! -f /var/lib/clamav/main.cvd ]; then
    echo "Baixando banco de dados inicial do ClamAV..."
    freshclam --config-file=/etc/clamav/freshclam.conf
fi

# Iniciar daemon ClamAV em background
echo "Iniciando daemon ClamAV..."
clamd --config-file=/etc/clamav/clamd.conf &

# Aguardar ClamAV inicializar
sleep 5

# Iniciar workers Celery em background
echo "Iniciando workers Celery..."
celery -A app.services.task_service worker --loglevel=info &
celery -A app.services.task_service beat --loglevel=info &

# Iniciar aplicação web
echo "Iniciando aplicação web..."
exec uvicorn main:app --host 0.0.0.0 --port 8000
