FROM ubuntu:latest

RUN apt update
RUN apt install -yq qemu-system-mips
RUN apt clean


RUN mkdir /app
WORKDIR /app
COPY ./run.sh ./
COPY ./vmlinuz ./
COPY ./initrd ./

EXPOSE 1337
CMD "./run.sh"