FROM python:3.9

ENV HOME /root

WORKDIR /root

COPY . .

COPY ./image .

RUN pip install pymongo
RUN pip install bcrypt

EXPOSE 8000

ADD https://github.com/ufoscout/docker-compose-wait/releases/download/2.2.1/wait /wait
RUN chmod +x /wait

CMD /wait && python server.py
