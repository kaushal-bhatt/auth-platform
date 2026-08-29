# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1 — build the executable Spring Boot jar.
# Build context is the repository ROOT because :auth-service depends on the
# sibling Gradle module :auth-jwt-lib (project(":auth-jwt-lib")), so both
# modules must be present to build. Build with:  docker build -t auth-service .
# ---------------------------------------------------------------------------
FROM eclipse-temurin:21-jdk AS build
WORKDIR /workspace

# Copy the Gradle wrapper + build scripts first so dependency resolution can be
# cached across source-only changes.
COPY gradlew settings.gradle.kts build.gradle.kts gradle.properties ./
COPY gradle ./gradle
COPY auth-jwt-lib/build.gradle.kts ./auth-jwt-lib/
COPY auth-service/build.gradle.kts ./auth-service/

# The committed gradle.properties points the JVM at the Windows OS trust store
# (trustStoreType=Windows-ROOT) for a Zscaler-intercepting dev machine. That
# provider does not exist on Linux and would fail every HTTPS dependency
# download here, so replace it with a plain container-appropriate JVM arg. The
# JDK's own cacerts trusts Maven Central fine in a normal container network.
RUN sed -i 's#^org.gradle.jvmargs=.*#org.gradle.jvmargs=-Xmx1536m#' gradle.properties \
    && chmod +x gradlew

# Warm the dependency cache (best-effort; ignore failure so a source-only build still works).
RUN ./gradlew :auth-service:dependencies --no-daemon -q > /dev/null 2>&1 || true

# Now the sources.
COPY auth-jwt-lib/src ./auth-jwt-lib/src
COPY auth-service/src ./auth-service/src

RUN ./gradlew :auth-service:bootJar --no-daemon \
    && cp "$(ls auth-service/build/libs/*.jar | grep -v -- '-plain.jar')" /workspace/app.jar

# ---------------------------------------------------------------------------
# Stage 2 — minimal JRE runtime.
# ---------------------------------------------------------------------------
FROM eclipse-temurin:21-jre AS runtime
WORKDIR /app

# Run as a non-root user.
RUN groupadd --system app && useradd --system --gid app --home /app app
COPY --from=build /workspace/app.jar /app/app.jar
USER app

EXPOSE 8080

# Tuned for a small single-VM host (see deploy/DEPLOY.md): cap heap to a share
# of the container memory and use the low-footprint serial collector. Override at
# deploy time if you give the container more memory.
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=55 -XX:+UseSerialGC -XX:+ExitOnOutOfMemoryError"

# Every runtime secret/config value is supplied via environment variables (see
# deploy/.env.example) — nothing environment-specific is baked into this image.
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
