FROM python:3.12-slim

# Set the working directory
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Install the dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install gunicorn

#install ping
RUN apt-get update && apt-get install -y iputils-ping

# Copy the application code
COPY . .

# Expose the port the app runs on
EXPOSE 5000

# Define the command to run the application
# Setting --access-logfile and --error-logfile to - sends logs to stdout/stderr
# Setting --capture-output captures stdout/stderr from the application
# Setting --log-level debug increases verbosity of Gunicorn's logs
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--access-logfile", "-", "--error-logfile", "-", "--capture-output", "--log-level", "debug", "app:app"]