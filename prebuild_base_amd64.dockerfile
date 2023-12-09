FROM ubuntu
RUN apt-get install
RUN apt-get update 
RUN apt-get -y install clang 
RUN apt-get -y install libpq-dev 
RUn apt-get -y install libc6-dev
