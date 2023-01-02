#!/bin/bash

if [ $# -ne 1 ]
then
  echo -e "Error, use: cipher-config <AES_KEY>"
else 
  java -cp target/ciphered-video-server.jar utils.cipherutils.EncryptConfig cipher "$1" "movies/plain/cryptoconfig.json" "movies/ciphered/cryptoconfig.json.enc"
fi