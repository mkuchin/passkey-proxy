FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /app
COPY gradlew gradlew.bat ./
COPY gradle/ gradle/
RUN ./gradlew --version
COPY build.gradle settings.gradle ./
RUN ./gradlew dependencies --no-daemon -q
COPY src/ src/
RUN ./gradlew bootJar --no-daemon -q

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=build /app/build/libs/passkey-proxy-*.jar app.jar

# Copy default config — mount /app/config as a volume in production
# so that credentials.yml (written at runtime) persists across restarts.
COPY config/ config/

VOLUME /app/config
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
