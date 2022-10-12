FROM openjdk:17

COPY target/ciphered-video-server.jar ciphered-video-server.jar
COPY movies/plain/* .
COPY movies/cryptoconfig.json .

CMD java -cp ciphered-video-server.jar server.StreamServer cars.dat localhost 7777