FROM maven:3.9-eclipse-temurin-17@sha256:036d1a6f2965e4368157bb87f02cd31652a96918a26f7eb5ae45a0aa33f2cb8e AS builder

WORKDIR /app

COPY . .

RUN --mount=type=cache,target=/root/.m2 mvn clean package -Dmaven.test.skip=true

FROM eclipse-temurin:17-jre@sha256:07c1f0f0c3f3c714cea7a9250a8418ec329baa2cea1f77dcda2a7332ff937633
RUN mkdir -p /etc/contrast/java/

WORKDIR /app

COPY --from=builder /app/target/dataservice-0.0.1-SNAPSHOT.jar    ./dataservice-0.0.1-SNAPSHOT.jar


EXPOSE 8080

CMD ["java","-jar", "./dataservice-0.0.1-SNAPSHOT.jar"]
