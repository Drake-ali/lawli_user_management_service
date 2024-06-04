# Use the official Azure Functions Python image from Docker Hub
FROM mcr.microsoft.com/azure-functions/python:3.0-python3.8

# Install additional packages if needed
# RUN apt-get update && apt-get install -y <package-name>

# Set the working directory
WORKDIR /home/site/wwwroot

# Copy all files to the working directory
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set the startup command to start Azure Functions host
CMD ["python", "-m", "azure_functions_worker"]

# Specify the runtime version and architecture
ENV FUNCTIONS_WORKER_RUNTIME python
ENV FUNCTIONS_EXTENSION_VERSION ~4

# Optional: Expose port 80
EXPOSE 80
