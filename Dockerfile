# Usage:

## Build the docker image, and tag it with name 'harness'
# docker build -t harnesses

## (Apple silicon users)
# docker build --platform=linux/amd64 -t harness .

## Run the image with your local filesystem mounted. Any edits you make 
## locally will be copied into the docker image. 
# docker run -v `pwd`:/build -ti harness bash

FROM debian:stable-slim as builder

# gdb and vim included for quality of life only.
RUN apt-get update && apt-get install -y build-essential libc6-dbg gdb vim
WORKDIR /mayhem
COPY . .

## Build all directories that start with "harness"
RUN ./build_harnesses.sh


## The fastest startup times. Uncomment only after all other harnessing done.
#FROM debian:stable-slim
#WORKDIR /mayhem
#COPY --from=builder /mayhem .