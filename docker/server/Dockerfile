FROM openjdk:17

RUN mkdir -p movies/ciphered

COPY target/ciphered-video-server.jar ciphered-video-server.jar
# TODO: Eventually stop sending plain movies
COPY movies/plain/* .
COPY movies/ciphered/* movies/ciphered

CMD java -cp ciphered-video-server.jar Server cars.dat localhost 7777