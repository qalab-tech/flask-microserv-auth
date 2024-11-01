# Add the basic Python image
FROM python:3.11-slim


# Set the working directory
WORKDIR /app

# Install all system dependencies, including CMake and other libraries
RUN apt-get update && apt-get install -y \
    tzdata \
    gcc \
    g++ \
    cmake \
    libpq-dev \
    libffi-dev \
    python3-dev \
    build-essential \
    --no-install-recommends && rm -rf /var/lib/apt/lists/*

# Upgrade pip
RUN pip install --upgrade pip

# Copy requirements.txt and install all the dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy other application files
COPY . .

# Expose port 5001
EXPOSE 5001

# Run Flask app with Gunicorn
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5001", "app:app"]
