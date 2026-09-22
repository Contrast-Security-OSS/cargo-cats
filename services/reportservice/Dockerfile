FROM maven:3.9-eclipse-temurin-17@sha256:42a3ac393abbc64dae6c96703e5ead2e921fe9103371ac58b5b404b0d6a26502 AS builder

WORKDIR /app

# Copy pom.xml and download dependencies (for better layer caching)
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code and build
COPY src ./src
RUN mvn package -DskipTests

# Runtime stage
FROM tomcat:9.0-jdk17@sha256:18dc1e23172bacff39c89582938df34f8044818eed53f65809ebec068b9c2f52

# Remove default Tomcat applications
RUN rm -rf /usr/local/tomcat/webapps/*

# Copy the built WAR file
COPY --from=builder /app/target/reportservice.war /usr/local/tomcat/webapps/ROOT.war

# Expose Tomcat port
EXPOSE 8080

ENV CATALINA_OPTS="-Xms256m -Xmx512m"

# Start Tomcat
CMD ["catalina.sh", "run"]
