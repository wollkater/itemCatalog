FROM python:3

RUN mkdir /usr/src/app
WORKDIR /usr/src/app
RUN pip install gunicorn --no-cache-dir
RUN pip install flask --no-cache-dir
RUN pip install oauth2client --no-cache-dir
RUN pip install  sqlalchemy --no-cache-dir
RUN pip install  requests --no-cache-dir
RUN pip install  psycopg2 --no-cache-dir

ENV FLASK_APP=itemCatalog.py
CMD flask db upgrade

COPY . .
