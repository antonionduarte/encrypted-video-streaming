FROM openjdk:17

COPY target/ciphered-video-server.jar ciphered-video-server.jar
ADD config/server/ config/server/
ADD config/common/ config/common/
ADD certs/server/ certs/server/
ADD certs/common/ certs/common/
ADD movies/ciphered/ movies/ciphered/

CMD java -cp ciphered-video-server.jar Server
