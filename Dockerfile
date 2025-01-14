FROM openjdk:17-jdk
EXPOSE 9091
ADD target/user-service.jar user-service.jar
ENTRYPOINT ["java","-jar","/user-service.jar"]
