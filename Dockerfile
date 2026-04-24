# Use a lightweight Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy the scanner script
COPY port.scanner.py .

# Expose the dashboard port
EXPOSE 5050

# Run the scanner with help by default
ENTRYPOINT ["python", "port.scanner.py"]
CMD ["--help"]
