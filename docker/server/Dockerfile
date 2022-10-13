FROM openjdk:17

RUN mkdir -p movies/ciphered

COPY target/ciphered-video-server.jar ciphered-video-server.jar
COPY movies/ciphered/* movies/ciphered/

CMD java -cp ciphered-video-server.jar Server movies/ciphered/cars.dat.enc 127.0.0.1 9999