FROM openjdk:17

RUN mkdir -p movies/ciphered
RUN mkdir -p certs/server
RUN mkdir -p certs/common

COPY target/ciphered-video-server.jar ciphered-video-server.jar
COPY movies/ciphered/* movies/ciphered/
COPY config/proxy-cryptoconfig.json config/
COPY certs/server/* certs/server/
COPY certs/common/* certs/common/

CMD java -cp ciphered-video-server.jar Server
