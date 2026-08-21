FROM maven:3.9-eclipse-temurin-17@sha256:b1420375ab2a5f3ef6e0f355367bff4096e23bdea2191af2b95f9f1c71984690 AS builder

WORKDIR /app

COPY . .

RUN --mount=type=cache,target=/root/.m2 mvn clean package -Dmaven.test.skip=true

FROM eclipse-temurin:17-jre@sha256:86a68aa80fe5dcc61ca191d7eda9140229641b6a6b84954b4fd4455e149047bc
RUN mkdir -p /etc/contrast/java/

WORKDIR /app

COPY --from=builder /app/target/dataservice-0.0.1-SNAPSHOT.jar    ./dataservice-0.0.1-SNAPSHOT.jar


EXPOSE 8080

CMD ["java","-jar", "./dataservice-0.0.1-SNAPSHOT.jar"]
