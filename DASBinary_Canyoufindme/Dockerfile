FROM ubuntu:18.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
    sed -i '/security/d' /etc/apt/sources.list && \
    apt-get update && apt-get -y dist-upgrade && \
    apt-get install -y lib32z1 xinetd libstdc++6 lib32stdc++6 && \
    echo 'ctf - nproc 1500' >>/etc/security/limits.conf && \
    useradd -U -m ctf && \
    mkdir -p /home/ctf && \
    cp -R /lib* /home/ctf && \
    mkdir /home/ctf/usr && \
    cp -R /usr/lib* /home/ctf/usr/ && \
    mkdir /home/ctf/bin && \
    cp /bin/sh /home/ctf/bin && \
    cp /bin/ls /home/ctf/bin && \
    cp /bin/cat /home/ctf/bin && \
    chown -R root:ctf /home/ctf && \
    chmod -R 750 /home/ctf && \
    mkdir /home/ctf/dev && \
    mknod /home/ctf/dev/null c 1 3 && \
    mknod /home/ctf/dev/zero c 1 5 && \
    mknod /home/ctf/dev/random c 1 8 && \
    mknod /home/ctf/dev/urandom c 1 9 && \
    chmod 666 /home/ctf/dev/* && \
    apt-get clean 

COPY ./   /home/ctf

RUN mv /home/ctf/ctf.xinetd /etc/xinetd.d/ctf && \
    rm /home/ctf/docker-compose.yml && \
    rm /home/ctf/Dockerfile && \
    mv /home/ctf/start.sh / && \
    chmod +x /home/ctf/problem/* && \
    cp /home/ctf/flag / && \
    mv /home/ctf/problem/* /home/ctf/ && \
    chmod +x /start.sh 

WORKDIR /home/ctf

CMD /start.sh

EXPOSE 12000
