#!/bin/bash

# A simple script in order to create
# or destroy the docker container for the iot platform

if [[ $# -eq 0 ]] ; then
  echo 'list : list of containers.'
  echo 'start : start the Iot Platform.'
  echo 'destroy : stop and remove the running containers.'
  exit 0
fi

if [ "$1" == "start" ]; then
  cd docker_compose/ && sudo docker-compose up
elif [ "$1" == "list" ]; then 
  sudo docker container list
elif [ "$1" == "destroy" ]; then
  for container in "$(sudo docker ps --format '{{.ID}}')"
  do
    echo $container
    sudo docker stop $container
    sudo docker rm $container
  done
else
  echo "Give correct argument"
fi
