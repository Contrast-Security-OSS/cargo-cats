FROM maven:3.9-eclipse-temurin-11@sha256:72b9e4bb485382967b1cae2028d5f1ac765403d964d864c7b107f740d1a5d3d7 AS builder

WORKDIR /app

COPY . .

RUN --mount=type=cache,target=/root/.m2 mvn clean package -Dmaven.test.skip=true

FROM eclipse-temurin:11-jre-jammy@sha256:703b6fe9df7ce218567fbe59d2ecf7a5d5313000b6ff5c9d2c77a45b34ceda2d

WORKDIR /app

# Create logs directory for log4j file appender
RUN mkdir -p logs

# Copy the JAR file from the builder stage
COPY --from=builder /app/target/frontgateservice-0.0.1-SNAPSHOT.jar app.jar

# Expose the port
EXPOSE 8081

ENTRYPOINT ["java", "-Dcom.sun.jndi.ldap.object.trustSerialData=true", "-jar", "app.jar"]
