FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cat.jpg .
COPY addresses.ser .
COPY payload.ser .
#COPY app.py .
#COPY templates/ ./templates/

EXPOSE 5000

CMD ["python", "app.py"]
