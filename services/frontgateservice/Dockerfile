FROM maven:3.9-eclipse-temurin-11@sha256:5818ee89bddd09cc7b265bea1919c5088f82a4e17f0adc104e12e94cb26bea03 AS builder

WORKDIR /app

COPY . .

RUN --mount=type=cache,target=/root/.m2 mvn clean package -Dmaven.test.skip=true

FROM eclipse-temurin:11-jre-jammy@sha256:e8acde9cc75b96765f005857cfeb7f826409177482c3f70400d5a94328689d56

WORKDIR /app

# Create logs directory for log4j file appender
RUN mkdir -p logs

# Copy the JAR file from the builder stage
COPY --from=builder /app/target/frontgateservice-0.0.1-SNAPSHOT.jar app.jar

# Expose the port
EXPOSE 8081

ENTRYPOINT ["java", "-Dcom.sun.jndi.ldap.object.trustSerialData=true", "-jar", "app.jar"]
