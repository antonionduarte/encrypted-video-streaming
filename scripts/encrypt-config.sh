#!/bin/bash

if [ $# -eq 0 ] 
then
  echo -e "Error, use: cipher-config <AES_KEY>"
else 
  java -cp target/ciphered-video-server.jar cipherdata.EncryptConfig cipher "$1" "movies/plain/cryptoconfig.json" "movies/ciphered/cryptoconfig.json.enc"
fi