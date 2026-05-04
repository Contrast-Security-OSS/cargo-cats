FROM maven:3.9-eclipse-temurin-11@sha256:1efab398c1f014f6596cb60e5b4b45b71c7207720775b5fef7a9af59076a7c19 AS builder

WORKDIR /app

COPY . .

RUN --mount=type=cache,target=/root/.m2 mvn clean package -Dmaven.test.skip=true

FROM eclipse-temurin:11-jre-jammy@sha256:2e02672c6ef67a09a0886b4a4e9e8e0516c67d5de14f7c26e67662717b1826a9

WORKDIR /app

# Create logs directory for log4j file appender
RUN mkdir -p logs

# Copy the JAR file from the builder stage
COPY --from=builder /app/target/frontgateservice-0.0.1-SNAPSHOT.jar app.jar

# Expose the port
EXPOSE 8081

# Run the application with unsafe serialization enabled for log4shell demo
ENTRYPOINT ["java", "-Dorg.apache.commons.collections.enableUnsafeSerialization=true", "-jar", "app.jar"]
