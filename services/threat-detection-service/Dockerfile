FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY services/threat-detection-service/target/*.jar app.jar
EXPOSE 8082
ENTRYPOINT ["java", "-jar", "app.jar"]
