FROM maven:3.9-eclipse-temurin-17@sha256:b1420375ab2a5f3ef6e0f355367bff4096e23bdea2191af2b95f9f1c71984690 AS builder

WORKDIR /app

# Copy pom.xml and download dependencies (for better layer caching)
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code and build
COPY src ./src
RUN mvn package -DskipTests

# Runtime stage
FROM tomcat:9.0-jdk17@sha256:9cdcd54e9dcd7523e1735dfe7acb63fdb0235ef4b8f58f58dd3affd2ef413826

# Remove default Tomcat applications
RUN rm -rf /usr/local/tomcat/webapps/*

# Copy the built WAR file
COPY --from=builder /app/target/reportservice.war /usr/local/tomcat/webapps/ROOT.war

# Expose Tomcat port
EXPOSE 8080

ENV CATALINA_OPTS="-Xms256m -Xmx512m"

# Start Tomcat
CMD ["catalina.sh", "run"]
