FROM maven:3.9-eclipse-temurin-17@sha256:42a3ac393abbc64dae6c96703e5ead2e921fe9103371ac58b5b404b0d6a26502 AS builder

WORKDIR /app

COPY . .

RUN --mount=type=cache,target=/root/.m2 mvn clean package -Dmaven.test.skip=true

FROM eclipse-temurin:17-jre@sha256:bd25c61779663bc2df8ced059f1cc114fafc073afe16125c13fcc3a37fecd845
RUN mkdir -p /etc/contrast/java/

WORKDIR /app

COPY --from=builder /app/target/aiservice-0.0.1-SNAPSHOT.jar ./aiservice-0.0.1-SNAPSHOT.jar

EXPOSE 8080

CMD ["java", "-jar", "./aiservice-0.0.1-SNAPSHOT.jar"]
