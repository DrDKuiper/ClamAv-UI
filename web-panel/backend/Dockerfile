FROM python:3.11-slim

# Definir diretório de trabalho
WORKDIR /app

# Instalar dependências do sistema
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements e instalar dependências Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código da aplicação
COPY . .

# Criar usuário não-root
RUN useradd -m -u 1000 clamav-user && \
    chown -R clamav-user:clamav-user /app

# Criar diretórios necessários
RUN mkdir -p /var/quarantine/clamav && \
    mkdir -p /var/log/clamav && \
    chown -R clamav-user:clamav-user /var/quarantine && \
    chown -R clamav-user:clamav-user /var/log/clamav

# Configurar ClamAV
COPY docker/clamd.conf /etc/clamav/clamd.conf
COPY docker/freshclam.conf /etc/clamav/freshclam.conf

# Script de inicialização
COPY docker/start.sh /start.sh
RUN chmod +x /start.sh

# Expor portas
EXPOSE 8000 3310

# Usar usuário não-root
USER clamav-user

# Comando de inicialização
CMD ["/start.sh"]
