FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Install iptables inside the container
RUN apt-get update && apt-get install -y iptables && rm -rf /var/lib/apt/lists/*

# Copy requirements first (Docker caches this layer)
# So if only code changes, pip install doesn't re-run
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all detector source files
COPY . .

# Create audit log directory
RUN mkdir -p /var/log/detector

# Run the daemon
CMD ["python", "main.py"]
