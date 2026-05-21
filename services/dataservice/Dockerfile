FROM maven:3.9-eclipse-temurin-17@sha256:32ce79e40d744b18c6ce9fe65d6b58189cbabc938cfeff657a534a359a5d3f92 AS builder

WORKDIR /app

COPY . .

RUN --mount=type=cache,target=/root/.m2 mvn clean package -Dmaven.test.skip=true

FROM eclipse-temurin:17-jre@sha256:0d79988c68791ce864fe39d149ab1dc84f680539dca77ee7f6f3b041ad7f2f43
RUN mkdir -p /etc/contrast/java/

WORKDIR /app

COPY --from=builder /app/target/dataservice-0.0.1-SNAPSHOT.jar    ./dataservice-0.0.1-SNAPSHOT.jar


EXPOSE 8080

CMD ["java","-jar", "./dataservice-0.0.1-SNAPSHOT.jar"]
