FROM maven:3.9-eclipse-temurin-11@sha256:56a702d1b60a25dd3725782e85ceafc95a1a772d5ab03e5230aefc0f9d980a0c AS builder

WORKDIR /app

COPY . .

RUN --mount=type=cache,target=/root/.m2 mvn clean package -Dmaven.test.skip=true

FROM eclipse-temurin:11-jre-jammy@sha256:40f4f041471e1288071281c7723b4706f1bb8f60a04acbf34b6bb84ac064de50

WORKDIR /app

# Create logs directory for log4j file appender
RUN mkdir -p logs

# Copy the JAR file from the builder stage
COPY --from=builder /app/target/frontgateservice-0.0.1-SNAPSHOT.jar app.jar

# Expose the port
EXPOSE 8081

# Run the application with unsafe serialization enabled for log4shell demo
ENTRYPOINT ["java", "-Dorg.apache.commons.collections.enableUnsafeSerialization=true", "-jar", "app.jar"]
