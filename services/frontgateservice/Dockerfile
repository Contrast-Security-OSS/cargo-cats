FROM maven:3.9-eclipse-temurin-11 AS builder

WORKDIR /app

COPY . .

RUN --mount=type=cache,target=/root/.m2 mvn clean package -Dmaven.test.skip=true

FROM eclipse-temurin:11-jre-jammy

WORKDIR /app

# Create logs directory for log4j file appender
RUN mkdir -p logs

# Copy the JAR file from the builder stage
COPY --from=builder /app/target/frontgateservice-0.0.1-SNAPSHOT.jar app.jar

# Expose the port
EXPOSE 8081

# Run the application with unsafe serialization enabled for log4shell demo
ENTRYPOINT ["java", "-Dorg.apache.commons.collections.enableUnsafeSerialization=true", "-jar", "app.jar"]
