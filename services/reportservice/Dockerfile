FROM maven:3.9-eclipse-temurin-17 AS builder

WORKDIR /app

# Copy pom.xml and download dependencies (for better layer caching)
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code and build
COPY src ./src
RUN mvn package -DskipTests

# Runtime stage
FROM tomcat:9.0-jdk17

# Remove default Tomcat applications
RUN rm -rf /usr/local/tomcat/webapps/*

# Copy the built WAR file
COPY --from=builder /app/target/reportservice.war /usr/local/tomcat/webapps/ROOT.war

# Expose Tomcat port
EXPOSE 8080

ENV CATALINA_OPTS="-Xms256m -Xmx512m"

# Start Tomcat
CMD ["catalina.sh", "run"]
