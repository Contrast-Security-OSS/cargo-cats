FROM maven:3.9-eclipse-temurin-17 AS builder

WORKDIR /app

COPY . .

RUN --mount=type=cache,target=/root/.m2 mvn clean package -Dmaven.test.skip=true

FROM eclipse-temurin:17-jre
RUN mkdir -p /etc/contrast/java/

WORKDIR /app

COPY --from=builder /app/target/aiservice-0.0.1-SNAPSHOT.jar ./aiservice-0.0.1-SNAPSHOT.jar

EXPOSE 8080

CMD ["java", "-jar", "./aiservice-0.0.1-SNAPSHOT.jar"]
