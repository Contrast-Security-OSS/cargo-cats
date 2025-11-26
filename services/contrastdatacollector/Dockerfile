FROM python:3.9-slim

# Build args for user and home
ARG UID=1001
ARG GID=1001
ARG USER=appuser
ARG HOME=/home/appuser

# Set HOME environment variable
ENV HOME=${HOME}

WORKDIR /app

# Create non-root user
RUN groupadd -g ${GID} ${USER} \
    && useradd -m -u ${UID} -g ${GID} -d ${HOME} ${USER}

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .

# Change ownership of directories
RUN chown -R ${USER}:0 /app ${HOME} && \
    chmod -R g=u /app ${HOME}

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Start the application
CMD ["python", "app.py"]
