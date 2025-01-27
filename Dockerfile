# Use Maven image to build the project
FROM maven:3.9.4-eclipse-temurin-17 AS build

# Set the working directory
WORKDIR /app

# Copy the Maven project files into the container
COPY pom.xml .
COPY src ./src

# Build the Maven project
RUN mvn clean package

# Use a lightweight JDK for runtime
FROM openjdk:17-jdk-slim

# Set the working directory for the runtime container
WORKDIR /app

# Copy the built jar file from the Maven build container
COPY --from=build /app/target/*.jar app.jar

# Expose the port used by your application
EXPOSE 5000-6000

# Command to run the application
CMD ["java", "-cp", "app.jar", "bmstu.kibamba.Runner", "node-1", "5001", "127.0.0.1", "Coordinator"]
