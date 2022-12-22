FROM openjdk:17

COPY target/ciphered-video-server.jar ciphered-video-server.jar
ADD config/proxy/ config/proxy/
ADD config/common/ config/common/
ADD certs/proxy/ certs/proxy/
ADD certs/common/ certs/common/

CMD java -cp ciphered-video-server.jar Proxy movies/ciphered/cars.dat.enc
