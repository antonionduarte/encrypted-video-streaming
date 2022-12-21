FROM openjdk:17

RUN mkdir -p config/proxy

COPY target/ciphered-video-server.jar ciphered-video-server.jar
COPY config/proxy/config.properties config/proxy
COPY config/proxy-cryptoconfig.json config/

CMD java -cp ciphered-video-server.jar Proxy