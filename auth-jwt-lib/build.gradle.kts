plugins {
    `java-library`
    `maven-publish`
}

// Consumers of an authentication library need to be able to read it, so the publication carries
// a javadoc jar and a sources jar alongside the binary jar.
java {
    withJavadocJar()
    withSourcesJar()
}

// Pinned to the versions Spring Boot 3.3.4 itself manages, so a consumer on Boot 3.3.x sees no
// version conflict and a consumer on a newer Boot upgrades these transparently via its own BOM.
val springBootVersion = "3.3.4"
val springFrameworkVersion = "6.1.13"
val jakartaServletVersion = "6.0.0"
val slf4jVersion = "2.0.16"
val lombokVersion = "1.18.34"

dependencies {
    // Public api surface: JwksClient.getKey returns Optional<RSAKey>, so nimbus types leak into
    // this library's own signatures and every consumer needs them on its compile classpath.
    api("com.nimbusds:nimbus-jose-jwt:9.40")

    // Spring Boot's configuration/condition model, genuinely needed at runtime by the
    // auto-configuration. Deliberately NOT spring-boot-starter-web: in a java-library,
    // `implementation` still lands on runtimeElements, so the starter would push
    // spring-boot-starter-tomcat (tomcat-embed-core) and logback-classic onto every consumer -
    // giving a host that runs on Jetty/Undertow an embedded Tomcat on its runtime classpath, and
    // a host that binds slf4j to log4j2 a second slf4j binding. This mirrors what
    // spring-boot-autoconfigure itself depends on: the container is the host's choice.
    implementation("org.springframework.boot:spring-boot-autoconfigure:$springBootVersion")
    implementation("org.springframework.boot:spring-boot:$springBootVersion")
    implementation("org.springframework:spring-context:$springFrameworkVersion")
    implementation("org.springframework:spring-core:$springFrameworkVersion")

    // Logging facade only - NEVER a binding. The host application picks and supplies the binding
    // (logback, log4j2, ...); shipping one from a library is how a consumer ends up with two.
    implementation("org.slf4j:slf4j-api:$slf4jVersion")

    // The servlet api and the spring web stack are guaranteed to be present in the servlet web
    // application this library is designed to run inside (the auto-configuration is
    // @ConditionalOnWebApplication(SERVLET) and contributes nothing without one), so they are
    // compile-only here and supplied by the host at runtime.
    compileOnly("org.springframework:spring-webmvc:$springFrameworkVersion")
    compileOnly("org.springframework:spring-web:$springFrameworkVersion")
    compileOnly("jakarta.servlet:jakarta.servlet-api:$jakartaServletVersion")

    compileOnly("org.projectlombok:lombok:$lombokVersion")
    annotationProcessor("org.projectlombok:lombok:$lombokVersion")

    testImplementation("org.springframework.boot:spring-boot-starter-test:$springBootVersion") {
        exclude(group = "org.junit.vintage", module = "junit-vintage-engine")
    }
    // The library's own tests have to stand in for the host and supply the web stack and servlet
    // api that are compileOnly above.
    testImplementation("org.springframework:spring-webmvc:$springFrameworkVersion")
    testImplementation("org.springframework:spring-web:$springFrameworkVersion")
    testImplementation("jakarta.servlet:jakarta.servlet-api:$jakartaServletVersion")
    testImplementation("org.mockito:mockito-core:5.12.0")
    testCompileOnly("org.projectlombok:lombok:$lombokVersion")
    testAnnotationProcessor("org.projectlombok:lombok:$lombokVersion")
}

// `implementation(project(":auth-jwt-lib"))` only ever resolves inside this repository's own
// settings.gradle.kts. For the library to be usable by the arbitrary Spring Boot service it is
// written for, it has to be publishable as a real artifact.
publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            // groupId/artifactId/version are inherited from the project: the root build.gradle.kts
            // sets group = "com.authplatform" and version = "0.1.0" for all projects, and the
            // artifactId defaults to the project name - so these coordinates resolve to
            // com.authplatform:auth-jwt-lib:0.1.0 and stay in step with the root build.
            from(components["java"])

            pom {
                name.set("auth-jwt-lib")
                description.set(
                    "Drop-in Spring Boot library that verifies RS256 JWTs against any standard "
                        + "RFC 7517 JWKS endpoint and enforces them on @JwtTokenVerification handlers."
                )
            }
        }
    }
}
