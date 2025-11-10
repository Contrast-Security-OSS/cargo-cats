FROM python:3.11-slim

# Arguments for user creation
ARG UID=1001
ARG GID=1001
ARG USERNAME=appuser
ARG HOME_DIR=/home/appuser

# Set environment variables
ENV HOME=${HOME_DIR}
ENV FLASK_APP=app.py
ENV FLASK_ENV=development
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Copy application code
COPY . .

# Create the user and set permissions
RUN groupadd -g ${GID} ${USERNAME} \
    && useradd -m -u ${UID} -g ${GID} -d ${HOME_DIR} -s /bin/bash ${USERNAME} \
    && mkdir -p /app/uploads \
    && chown -R ${UID}:0 /app ${HOME_DIR} \
    && chmod -R g=u /app ${HOME_DIR}

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port
EXPOSE 5000

# Switch to the newly created user
USER ${UID}

# Run the application with gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "app:app"]
