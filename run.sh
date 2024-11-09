#!/bin/bash

# Display options menu
echo "Please choose whether to enable profiling (cProfile):"
echo "1. Enable profiling"
echo "2. Disable profiling"

read -p "Enter option [1-2]: " profiling_choice

echo "Please choose how to run waf-prowler:"
echo "1. Run waf-prowler with memory..."
echo "2. Run waf-prowler without memory..."
echo "3. Run waf-prowler without memory and disable shortcut..."
echo "4. Run waf-prowler without memory and with reinforcement learning..."
echo "5. Run waf-prowler without memory and with reinforcement learning and without shortcut..."
echo "6. Clean up..."
echo "6. Exit"

read -p "Enter option [1-6]: " execution_choice

# Construct command based on choices
if [ "$profiling_choice" -eq 1 ]; then
    profile_command="python -m cProfile -o profile.stats"
    snakeviz_command="&& python -m snakeviz profile.stats --server"
else
    profile_command="python3"
    snakeviz_command=""
fi

# Build the command to execute
case $execution_choice in
    1)
        echo "Running waf-prowler with memory..."
        command="$profile_command main.py -m $snakeviz_command"
        ;;
    2)
        echo "Running waf-prowler without memory..."
        command="$profile_command main.py -m --disable-memory $snakeviz_command"
        ;;
    3)
        echo "Running waf-prowler without memory and disable shortcut..."
        command="$profile_command main.py -m --disable-memory -ds $snakeviz_command"
        ;;
    4)
        echo "Running waf-prowler without memory and with reinforcement learning..."
        command="$profile_command main.py -m --disable-memory --rl $snakeviz_command"
        echo $command
        ;;
    5)
        echo "Running waf-prowler without memory and with reinforcement learning and without shortcut..."
        command="$profile_command main.py -m --disable-memory --rl -ds $snakeviz_command"
        ;;
    6)
        echo "Cleaning up..."
        ./clean.sh
        exit 0
        ;;
    7)
        echo "Exiting the program"
        exit 0
        ;;
    *)
        echo "Invalid option. Please choose 1, 2, 3, 4, 5, or 6."
        exit 1
        ;;
esac

# Execute the command
if [ -n "$profile_command" ]; then
    eval "$command"
else
    eval "$command"
fi
