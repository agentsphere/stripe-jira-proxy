# Use an official slim Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Copy just the requirements file first to leverage Docker cache
COPY requirements.txt .

# Install pip dependencies
# --no-cache-dir reduces image size
# --upgrade pip ensures pip is up-to-date
RUN pip install --no-cache-dir --upgrade pip -r requirements.txt

# Copy the rest of the application code (app.py)
# Avoid copying sensitive files like .env into the image!
COPY app.py .

# Expose the port the app runs on (Flask default is 5000)
# This should match the port used in app.py (os.environ.get('PORT', 5000))
EXPOSE 5000

# Define the command to run the application
# Uses Flask's built-in server (good for development/simple cases)
# For production, consider using a WSGI server like Gunicorn:
# CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
CMD ["python", "app.py"]
