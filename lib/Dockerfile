FROM maven:3.6.3-openjdk-17-slim AS build

ARG PROJECT_ROOT_IN_CONTAINER

# In the ./src/main/resources folder, 1) application.properties, 2) logback-spring.xml and 3) [the filename of 'server.ssl.key-store' in your properties] should be located.
COPY .. $PROJECT_ROOT_IN_CONTAINER
USER root
WORKDIR $PROJECT_ROOT_IN_CONTAINER

RUN --mount=type=cache,target=/root/.m2 mvn -f $PROJECT_ROOT_IN_CONTAINER/pom.xml clean install

FROM openjdk:17-alpine

ARG PROJECT_ROOT_IN_CONTAINER
ARG FILE_STORAGE_ROOT_IN_CONTAINER
ARG JVM_XMS
ARG JVM_XMX

COPY --from=build $PROJECT_ROOT_IN_CONTAINER/ $PROJECT_ROOT_IN_CONTAINER

USER root
WORKDIR $PROJECT_ROOT_IN_CONTAINER

RUN cp $PROJECT_ROOT_IN_CONTAINER/target/*.jar  /app.jar

RUN ln -s $PROJECT_ROOT_IN_CONTAINER/.docker/entrypoint/run-app.sh /run-app.sh

RUN apk --no-cache add curl bash fontconfig ttf-dejavu

ENV PROJECT_ROOT_IN_CONTAINER=$PROJECT_ROOT_IN_CONTAINER
ENV FILE_STORAGE_ROOT_IN_CONTAINER=$FILE_STORAGE_ROOT_IN_CONTAINER
ENV JVM_XMS=$JVM_XMS
ENV JVM_XMX=$JVM_XMX
ENV RESOURCES_TYPE=$RESOURCES_TYPE

ENTRYPOINT sh /run-app.sh $PROJECT_ROOT_IN_CONTAINER $FILE_STORAGE_ROOT_IN_CONTAINER $JVM_XMS $JVM_XMX && /bin/sh