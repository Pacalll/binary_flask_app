# Use ubuntu as image
FROM debian:bullseye-slim

# install git, make, strace and gcc
RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y git strace
RUN apt-get install -y make gcc

# setting cwd, cloning git radare2 repo and install, create upload folder for volume mounting
WORKDIR /app
RUN git clone https://github.com/radareorg/radare2
WORKDIR /app/radare2
RUN ./sys/install.sh
WORKDIR /app
RUN mkdir "uploads"