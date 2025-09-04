#!/bin/zsh

protoc -I=. --descriptor_set_out=reload.desc reload.proto
echo "Done."