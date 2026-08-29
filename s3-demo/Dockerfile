# ==============================================================================
# Stage 1: Build stage (compile auth-lib & s3-demo Quarkus app)
# Uses BuildKit cache mount for /root/.m2 to cache Maven dependencies across builds
# ==============================================================================
FROM maven:3.9.9-eclipse-temurin-21 AS builder

WORKDIR /workspace

# 1. Build and install root auth-lib using persistent .m2 cache
COPY pom.xml ./root-pom.xml
COPY src ./src
RUN --mount=type=cache,target=/root/.m2 mvn -f root-pom.xml clean install

# 2. Build and package Quarkus s3-demo using persistent .m2 cache
COPY s3-demo/pom.xml ./s3-demo/pom.xml
COPY s3-demo/src ./s3-demo/src
RUN --mount=type=cache,target=/root/.m2 mvn -f s3-demo/pom.xml clean package -DskipTests

# ==============================================================================
# Stage 2: Runtime stage (Lightweight JRE 21)
# ==============================================================================
FROM eclipse-temurin:21-jre-jammy

ENV LANGUAGE='en_US:en'

WORKDIR /deployments

# Copy Quarkus fast-jar application layout
COPY --from=builder /workspace/s3-demo/target/quarkus-app/lib/ /deployments/lib/
COPY --from=builder /workspace/s3-demo/target/quarkus-app/*.jar /deployments/
COPY --from=builder /workspace/s3-demo/target/quarkus-app/app/ /deployments/app/
COPY --from=builder /workspace/s3-demo/target/quarkus-app/quarkus/ /deployments/quarkus/

EXPOSE 8080

USER 1001

ENV JAVA_OPTS="-Dquarkus.http.host=0.0.0.0 -Djava.util.logging.manager=org.jboss.logmanager.LogManager"
ENV JAVA_APP_JAR="/deployments/quarkus-run.jar"

ENTRYPOINT [ "sh", "-c", "java $JAVA_OPTS -jar $JAVA_APP_JAR" ]
