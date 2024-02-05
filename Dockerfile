# DOCKERFILE to host flask app with scapy endpoint to monitor network traffic
FROM python:3.8

# install ip package
RUN apt-get update && apt-get install -y iproute2

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirement.txt

# Make port 5000 available to the world outside this container
EXPOSE 5000

# RUN the app
CMD ["python", "app.py"]
