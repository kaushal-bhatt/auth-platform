# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1 — build the executable Spring Boot jar.
# Build context is the repository ROOT because :auth-service depends on the
# sibling Gradle module :auth-jwt-lib (project(":auth-jwt-lib")), so both
# modules must be present to build. Build with:  docker build -t auth-service .
# ---------------------------------------------------------------------------
# The official Gradle image, NOT temurin + the wrapper — and the version is
# pinned to exactly the one gradle/wrapper/gradle-wrapper.properties names, so
# local `./gradlew` builds and this one use the same Gradle.
#
# The wrapper downloads its distribution on first use, and that download is a
# redirect chain: services.gradle.org -> github.com ->
# release-assets.githubusercontent.com. The last host is blocked or throttled on
# an intercepting corporate network, and the wrapper gives up after
# networkTimeout (10s), so the build died with a SocketTimeoutException inside
# followRedirect before compiling a line.
#
# It only surfaced once the BuildKit cache had been pruned. The distribution
# lives in the cache MOUNT below, which is not the layer cache — so the warm-up
# step could report CACHED, never run, and leave the mount empty. A build that
# depends on a download it usually skips is a build that works until the day it
# does not.
#
# This image ships Gradle at /usr/bin/gradle and runs as root, so there is
# nothing to fetch and nothing to chmod.
FROM gradle:8.14.5-jdk21 AS build
WORKDIR /workspace

# Copy the build scripts first so dependency resolution can be cached across
# source-only changes. The wrapper is not copied any more — nothing here runs it.
COPY settings.gradle.kts build.gradle.kts gradle.properties ./
COPY auth-jwt-lib/build.gradle.kts ./auth-jwt-lib/
COPY auth-service/build.gradle.kts ./auth-service/

# The committed gradle.properties points the JVM at the Windows OS trust store
# (trustStoreType=Windows-ROOT) for a Zscaler-intercepting dev machine. That
# provider does not exist on Linux and would fail every HTTPS dependency
# download here, so replace it with a plain container-appropriate JVM arg. The
# JDK's own cacerts trusts Maven Central fine in a normal container network.
RUN sed -i 's#^org.gradle.jvmargs=.*#org.gradle.jvmargs=-Xmx1536m#' gradle.properties

# Stated rather than inherited. Root's HOME already puts it here, but the base
# image declares a volume at /home/gradle/.gradle, and a future version of it
# setting GRADLE_USER_HOME would move the dependency cache out from under the
# mount below without anything failing — just every build downloading the world
# again.
ENV GRADLE_USER_HOME=/root/.gradle

# A BuildKit cache mount makes GRADLE_USER_HOME survive BETWEEN builds rather
# than being discarded with the layer. Without it every CI build re-downloads
# the entire dependency graph, which is the slowest part of the build by far.
# `sharing=locked` stops two concurrent builds from corrupting the cache.

# Warm the dependency cache (best-effort; ignore failure so a source-only build still works).
RUN --mount=type=cache,target=/root/.gradle,sharing=locked \
    gradle :auth-service:dependencies --no-daemon -q > /dev/null 2>&1 || true

# Now the sources.
COPY auth-jwt-lib/src ./auth-jwt-lib/src
COPY auth-service/src ./auth-service/src

# The jar must be copied out inside THIS RUN: a cache mount is not part of the
# image, so anything written under /root/.gradle is gone once the step ends.
RUN --mount=type=cache,target=/root/.gradle,sharing=locked \
    gradle :auth-service:bootJar --no-daemon \
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
