FROM python:3.6-slim

RUN mkdir -p /opt/Cortex-Analyzers/custom_responders -p /usr/share/man/man1mkdir -p /usr/share/man/man1


RUN apt-get update
RUN apt-get install -y \
    gnupg2 \
    libmagic1 \
    libssl-dev \
    curl \
    openjdk-11-jre \
    default-jre-headless

RUN echo 'deb https://deb.thehive-project.org release main' | tee -a /etc/apt/sources.list.d/thehive-project.list && \
    curl --insecure https://raw.githubusercontent.com/TheHive-Project/TheHive/master/PGP-PUBLIC-KEY | apt-key add - && \
    update-ca-certificates

RUN apt-get update
RUN apt-get install -y cortex

RUN pip install --no-cache-dir pipenv httpie

ADD . /opt/Cortex-Analyzers/custom_responders/

RUN for responder_path in $(ls -d /opt/Cortex-Analyzers/custom_responders/*/); do\
    cd $responder_path; pipenv install --system --deploy --ignore-pipfile; \
    done

ENTRYPOINT ["/opt/cortex/bin/cortex"]
CMD ["-Dconfig.file=/etc/cortex/application.conf", "-Dlogger.file=/etc/cortex/logback.xml"]
