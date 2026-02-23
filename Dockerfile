FROM --platform=linux/amd64 ubuntu:22.04

RUN apt-get update && apt-get install -y nasm binutils && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Makefile .
COPY src/ src/

RUN make

ENTRYPOINT ["./negative_claw"]
