FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY services/log-ingestion-service/target/*.jar app.jar
EXPOSE 8081 5514
ENTRYPOINT ["java", "-jar", "app.jar"]
