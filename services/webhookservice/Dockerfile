FROM python:3.9-slim

# Build arguments for user setup
ARG UID=1001
ARG GID=1001
ARG USER=myuser
ARG HOME=/home/myuser

# Export HOME into the environment
ENV HOME=${HOME}

# Create group and user
RUN groupadd -g ${GID} ${USER} \
    && useradd -m -u ${UID} -g ${GID} -d ${HOME} ${USER}

# Set the working directory
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install gunicorn

# Install ping
RUN apt-get update && apt-get install -y iputils-ping && rm -rf /var/lib/apt/lists/*

# Copy the application code
COPY . .

# Ensure user owns the app directory
RUN chown -R ${USER}:0 /app ${HOME} && \
    chmod -R g=u /app ${HOME}

# Switch to non-root user
USER ${USER}

# Expose port
EXPOSE 5000

# Run app with gunicorn
#CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--access-logfile", "-", "--error-logfile", "-", "--capture-output", "--log-level", "debug", "app:app"]
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--access-logfile", "-", "--error-logfile", "-", "--capture-output", "--log-level", "debug", "--workers", "1", "--timeout", "60", "app:app"]
