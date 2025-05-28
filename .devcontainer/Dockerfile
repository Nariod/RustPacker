# Use an official Rust image as a parent image
FROM rust:latest

# Set the working directory
WORKDIR /workspace

# Install any additional dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the entire project directory into the container
COPY . .

# Build the project
RUN cargo build