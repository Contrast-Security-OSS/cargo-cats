FROM maven:3.9-eclipse-temurin-11 AS builder

WORKDIR /app

COPY . .

RUN --mount=type=cache,target=/root/.m2 mvn clean package -Dmaven.test.skip=true

FROM eclipse-temurin:11-jre-jammy

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

WORKDIR /app

# Create logs directory for log4j file appender
RUN mkdir -p logs

# Copy the JAR file from the builder stage
COPY --from=builder /app/target/frontgateservice-0.0.1-SNAPSHOT.jar app.jar

# Ensure user owns the application directory
RUN chown -R ${USER}:0 /app ${HOME} && \
    chmod -R g=u /app ${HOME}

USER ${UID}

# Expose the port
EXPOSE 8081

# Run the application with unsafe serialization enabled for log4shell demo
ENTRYPOINT ["java", "-Dorg.apache.commons.collections.enableUnsafeSerialization=true", "-jar", "app.jar"]
