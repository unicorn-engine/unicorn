FROM ubuntu

RUN apt-get update && \
    apt-get install -y software-properties-common lsb-release wget vim curl less && \
    apt-get clean all
RUN wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null
RUN apt-get update && apt-get install -y cmake pkg-config
