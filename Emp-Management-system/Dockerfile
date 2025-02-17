# Step 1: Use an OpenJDK base image
FROM openjdk:17-jdk-slim AS build

# Step 2: Set the working directory inside the container
WORKDIR /app

# Step 3: Copy the Maven project into the container
COPY pom.xml .
COPY src ./src

# Step 4: Build the application using Maven
RUN ./mvnw clean install -DskipTests

# Step 5: Use a lighter image for the final app image
FROM openjdk:17-jre-slim

# Step 6: Set the working directory
WORKDIR /app

# Step 7: Copy the JAR file from the build container to the final image
COPY --from=build /app/target/Emp-Management-system-0.0.1-SNAPSHOT.jar /app/Emp-Management-system.jar

# Step 8: Expose the port your app will run on
EXPOSE 8080

# Step 9: Run the application
ENTRYPOINT ["java", "-jar", "Emp-Management-system.jar"]
