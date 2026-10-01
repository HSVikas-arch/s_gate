# Use a tiny, resource-optimized Python environment
FROM python:3.11-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy the dependency file first to speed up image rebuilds
COPY requirements.txt .

# Install dependencies cleanly without saving useless cache data
RUN pip install --no-cache-dir -r requirements.txt

# Copy all your academic application files into the container
COPY . .

# Flask typically runs on port 5000
EXPOSE 5000

# Start your application up dynamically
CMD ["python", "app.py"]
