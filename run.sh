#!/bin/bash

# Display options menu
echo "Please choose an action:"
echo "1. Run waf-prowler with memory..."
echo "2. Run waf-prowler without memory..."
echo "3. Run waf-prowler without memory and disable shortcut..."
echo "4. Clean up..."
echo "5. Exit"

# Read user choice
read -p "Enter option [1-5]: " choice

case $choice in
    1)
        echo "Running waf-prowler with memory..."
        python3 main.py -m
        ;;
    2)
        echo "Running waf-prowler without memory..."
        python3 main.py -m --disable-memory
        ;;
    3)
        echo "Running waf-prowler without memory and disable shortcut..."
        python3 main.py --disable-memory -ds
        ;;
    4)
        echo "Cleaning up..."
        ./clean.sh
        ;;
    5)
        echo "Exiting the program"
        exit 0
        ;;
    *)
        echo "Invalid option. Please choose 1, 2, 3, 4, or 5."
        ;;
esac
