from python:3.6

ENV PYTHONUNBUFFERED 1

RUN apt update
RUN apt install -y libxmlsec1-dev

RUN mkdir /ssoauth
WORKDIR /ssoauth

ADD requirements.txt /ssoauth/
RUN pip install -r requirements.txt

ADD entrypoint.sh /ssoauth/
RUN chmod +x entrypoint.sh

ADD src/. /ssoauth/

EXPOSE 8080 

ENTRYPOINT ["/ssoauth/entrypoint.sh"]
