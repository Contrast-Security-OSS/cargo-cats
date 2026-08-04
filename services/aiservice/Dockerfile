FROM maven:3.9-eclipse-temurin-17@sha256:4015718012bbf1113ec6cfae2b950be328d90265ceb60f92b26c3ea7c4d14ee8 AS builder

WORKDIR /app

COPY . .

RUN --mount=type=cache,target=/root/.m2 mvn clean package -Dmaven.test.skip=true

FROM eclipse-temurin:17-jre@sha256:e4f018a55645ad204892e44eb35437518d7e108ba2a2dce305024ab371d24876
RUN mkdir -p /etc/contrast/java/

WORKDIR /app

COPY --from=builder /app/target/aiservice-0.0.1-SNAPSHOT.jar ./aiservice-0.0.1-SNAPSHOT.jar

EXPOSE 8080

CMD ["java", "-jar", "./aiservice-0.0.1-SNAPSHOT.jar"]
