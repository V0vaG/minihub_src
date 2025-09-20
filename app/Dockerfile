FROM python:3.9-slim

ARG VERSION
ENV VERSION=$VERSION

ARG B_NUM
ENV B_NUM=$B_NUM

ARG BRANCH
ENV BRANCH=$BRANCH

ARG IP
ENV IP=$IP

WORKDIR ~/

COPY ./requirements.txt .

RUN pip install -r requirements.txt

COPY . .

CMD gunicorn --timeout 120 -w 4 -b 0.0.0.0:5000 app:app

