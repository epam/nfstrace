FROM ubuntu:14.04.5

VOLUME /build
WORKDIR /build

RUN apt-get update \
    && apt-get install -y build-essential \
    automake make libpcap-dev software-properties-common \
    python-software-properties cmake \
    && add-apt-repository -y ppa:ubuntu-toolchain-r/test \
    && apt-get update \
    && apt-get install -y gcc-5 g++-5 \
    && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-5 60 --slave /usr/bin/g++ g++ /usr/bin/g++-5
