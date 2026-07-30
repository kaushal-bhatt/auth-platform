plugins {
    java
    id("org.springframework.boot") version "3.3.4"
    id("io.spring.dependency-management") version "1.1.6"
}

dependencyManagement {
    imports {
        mavenBom("org.springframework.boot:spring-boot-dependencies:3.3.4")
        // Spring Boot 3.3.4's BOM pins Testcontainers to 1.19.8, which bundles docker-java 3.3.6.
        // That client talks Docker API 1.32 - below the minimum API version modern Docker engines
        // (Engine 29.x reports MinAPIVersion 1.40) accept - so Testcontainers fails to find a valid
        // Docker environment with an HTTP 400. Importing the Testcontainers BOM last aligns every
        // testcontainers artifact on one newer version whose docker-java negotiates a supported API.
        mavenBom("org.testcontainers:testcontainers-bom:1.20.4")
    }
}

dependencies {
    implementation(project(":auth-jwt-lib"))

    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.liquibase:liquibase-core")
    implementation("org.postgresql:postgresql")
    implementation("com.nimbusds:nimbus-jose-jwt:9.40")
    implementation("com.webauthn4j:webauthn4j-core:0.24.0.RELEASE")

    compileOnly("org.projectlombok:lombok:1.18.34")
    annotationProcessor("org.projectlombok:lombok:1.18.34")

    testImplementation("org.springframework.boot:spring-boot-starter-test") {
        exclude(group = "org.junit.vintage", module = "junit-vintage-engine")
    }
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("org.testcontainers:junit-jupiter")
    testImplementation("org.testcontainers:postgresql")
    testCompileOnly("org.projectlombok:lombok:1.18.34")
    testAnnotationProcessor("org.projectlombok:lombok:1.18.34")
}

// note: useJUnitPlatform() and the java 21 toolchain are applied to every subproject by the
// root build.gradle.kts, so they are deliberately not repeated here.

tasks.withType<Test> {
    // Testcontainers' docker-java client otherwise talks to the daemon at an API version below
    // what a modern Docker engine accepts: Engine 29.x reports MinAPIVersion 1.40 and rejects any
    // request under 1.40 with a bare HTTP 400 ("Could not find a valid Docker environment"), which
    // fails every @Testcontainers integration test. The docker CLI dodges this by negotiating the
    // version down; docker-java does not here, so we pin the API version it sends to a value the
    // engine supports (1.44, shipped with Docker 25 and honoured by everything newer). docker-java
    // reads this from the `api.version` system property in the forked test JVM.
    systemProperty("api.version", "1.44")
}
