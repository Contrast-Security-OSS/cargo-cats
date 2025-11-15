FROM maven:3.9-eclipse-temurin-17 AS builder

WORKDIR /app

COPY . .

RUN --mount=type=cache,target=/root/.m2 mvn clean package -Dmaven.test.skip=true

# Base image
FROM eclipse-temurin:17-jre

# Build args for user and home
ARG UID=1001
ARG GID=1001
ARG USER=myuser
ARG HOME=/home/myuser

# Set HOME environment variable
ENV HOME=${HOME}

# Create non-root user
RUN groupadd -g ${GID} ${USER} \
    && useradd -m -u ${UID} -g ${GID} -d ${HOME} ${USER}

# Create folder for contrast (owned by user)
RUN mkdir -p /etc/contrast/java/ \
    && chown -R ${USER}:0 /etc/contrast/java/

WORKDIR /app

# Copy built JAR from builder stage
COPY --from=builder /app/target/dataservice-0.0.1-SNAPSHOT.jar ./dataservice-0.0.1-SNAPSHOT.jar

# Ensure user owns the application directory
RUN chown -R ${USER}:0 /app ${HOME} && \
    chmod -R g=u /app ${HOME}

# Switch to the non-root user
USER ${USER}

EXPOSE 8080

CMD ["java", "-jar", "./dataservice-0.0.1-SNAPSHOT.jar"]
