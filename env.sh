#!/bin/bash

#set -eu

name=sgx-learning
id=`docker ps -a | grep $name | awk '{print $1}'`

if [ -z "$id" ]; then
    ep=`pwd`
    epp=`echo $ep | grep scripts`
    if [ -n "$epp" ]; then
        # ignore script dir
        ep=$(echo $ep | awk -F '/[^/]*$' '{print $1}')
    fi

    docker run -v $ep:/root/sgx-learning --name $name -it baiduxlab/sgx-rust
else
    docker start $name
    docker exec -it $name bash
fi