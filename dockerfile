# Start from a base Python image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Install additional dependencies for Zeek and AWS
RUN apt-get update && apt-get install -y zeek

# Copy the application code
COPY . .

# Expose the necessary ports (if any)
EXPOSE 80

# Command to run the application
CMD ["python", "fortress.py"]