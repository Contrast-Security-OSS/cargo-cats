FROM maven:3.9-eclipse-temurin-11@sha256:d7fde65edb74e27c01909e8b7287f5da9e49913643912c412894feef77d8ed26 AS builder

WORKDIR /app

COPY . .

RUN --mount=type=cache,target=/root/.m2 mvn clean package -Dmaven.test.skip=true

FROM eclipse-temurin:11-jre-jammy@sha256:eca8fa395077325c4065446e99e79af91c7283f10600d7f8c11530493e38a07c

WORKDIR /app

# Create logs directory for log4j file appender
RUN mkdir -p logs

# Copy the JAR file from the builder stage
COPY --from=builder /app/target/frontgateservice-0.0.1-SNAPSHOT.jar app.jar

# Expose the port
EXPOSE 8081

ENTRYPOINT ["java", "-Dcom.sun.jndi.ldap.object.trustSerialData=true", "-jar", "app.jar"]
