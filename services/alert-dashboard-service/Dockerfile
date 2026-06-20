FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY services/alert-dashboard-service/target/*.jar app.jar
EXPOSE 8085
ENTRYPOINT ["java", "-jar", "app.jar"]
