FROM eclipse-temurin:21-jre-alpine
LABEL maintainer="watchtower"
WORKDIR /app
COPY services/api-gateway/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
