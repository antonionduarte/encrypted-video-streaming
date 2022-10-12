FROM openjdk:17

COPY target/ciphered-video-server.jar ciphered-video-server.jar
# TODO: Send ciphered movies
COPY movies/plain/* .
COPY movies/ciphered/* .

CMD java -cp ciphered-video-server.jar Server cars.dat localhost 7777