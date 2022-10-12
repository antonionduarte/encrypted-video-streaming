FROM openjdk:17

COPY target/ciphered-video-server.jar ciphered-video-server.jar
COPY movies/plain/* .

# CMD java -cp ciphered-video-server.jar server.StreamServer cars.dat localhost 7777
CMD java -cp ciphered-video-server.jar Main