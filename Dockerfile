FROM python:3.10.12-slim
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
RUN apt-get update && apt-get install -y libpcap-dev
EXPOSE 5001
ENTRYPOINT ["python"]
CMD ["app.py"]