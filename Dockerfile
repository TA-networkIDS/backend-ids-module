# Use a Python base image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /code

RUN apt-get update -y && apt-get install -y \
    # && apt-get install libpcap-dev \
    && rm -rf /var/lib/apt/lists/*


# Set JAVA_HOME and JVM_PATH environment variables
# ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
# ENV JVM_PATH=/usr/lib/jvm/java-11-openjdk-amd64/lib/server/libjvm.so
# ENV PATH=$JAVA_HOME/bin:$PATH

# RUN export JAVA_HOME

# Copy the requirements file into the container
COPY ./requirements.txt /code/requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

# Copy the application code into the container
COPY ./app /code/app
COPY ./trained_models /code/trained_models

EXPOSE 8008

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8888"]
# CMD ["fastapi", "dev", "app/main.py", "--host", "0.0.0.0", "--port", "8008"]