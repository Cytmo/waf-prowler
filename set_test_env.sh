#!/bin/bash

# Display options menu
echo "Please choose an action:"
echo "1. Start Docker service for test environment..."
echo "2. Stop Docker service for test environment..."
echo "3. Exit"

# Read user choice
read -p "Enter option [1-3]: " choice

case $choice in
    1)
        echo "Starting Docker service for test environment..."
        docker-compose -f test-envs/a-simple-waf/docker-compose.yml up -d
        ;;
    2)
        echo "Stopping Docker service for test environment..."
        docker-compose -f test-envs/a-simple-waf/docker-compose.yml down
        ;;
    3)
        echo "Exiting the program"
        exit 0
        ;;
    *)
        echo "Invalid option. Please choose 1, 2, or 3."
        ;;
esac
