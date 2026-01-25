# =========================
# BUILD STAGE
# =========================
FROM maven:3.9.9-eclipse-temurin-21-jammy AS build

WORKDIR /app

# Copy only what is needed to cache dependencies
COPY pom.xml .
COPY .mvn .mvn

# Download dependencies (cached layer)
RUN mvn -B -q dependency:go-offline

# Copy source and build
COPY src src
RUN mvn -B -q package -DskipTests


# =========================
# RUNTIME STAGE
# =========================
FROM eclipse-temurin:21-jre-jammy

# Create non-root user
RUN useradd -r -u 1001 springuser

WORKDIR /app

# JVM tuning for containers
ENV JAVA_OPTS="\
  -XX:MaxRAMPercentage=75 \
  -XX:+UseG1GC \
  -XX:+ExitOnOutOfMemoryError \
  -XX:+UseStringDeduplication \
  -Djava.security.egd=file:/dev/./urandom \
  -Dspring.profiles.active=prod"

# Copy only the final jar
COPY --from=build /app/target/*.jar app.jar

# Permissions
RUN chown springuser:springuser app.jar
USER springuser

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD wget -qO- http://localhost:8081/actuator/health || exit 1

ENTRYPOINT ["sh","-c","exec java $JAVA_OPTS -jar app.jar"]
