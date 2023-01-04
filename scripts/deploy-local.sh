#!/bin/bash

if [ "$#" != "1" ]; then
  echo "Usage: $0 <movie>"
  exit 1
fi

movie=$1

gnome-terminal -e "bash -c \"java -cp target/ciphered-video-server.jar Server; read -p 'Press enter to close terminal...'\"" &
sleep 2
gnome-terminal -e "bash -c \"java -cp target/ciphered-video-server.jar Proxy $movie; read -p 'Press enter to close terminal...'\"" &
