#!/bin/bash

# Check if an argument is provided
if [ -z "$1" ]; then
    echo "Error: No argument provided. Please provide one of the following: onos, osc, aic"
    exit 1
fi

# Determine the URLs file based on the argument
case $1 in
    onos)
        URLS_FILE="onos_links.txt"
        ;;
    osc)
        URLS_FILE="osc_links.txt"
        ;;
    aic)
        URLS_FILE="aic_links.txt"
        ;;
    *)
        echo "Error: Invalid argument. Please provide one of the following: onos, osc, aic"
        exit 1
        ;;
esac

# Remote branch
REMOTE_BRANCH="master"

# Check if the URLs file exists
if [ ! -f "$URLS_FILE" ]; then
    echo "Error: URLs file not found: $URLS_FILE"
    exit 1
fi

# Loop through each URL in the file and run git subtree command
while IFS= read -r url; do
    # Extract the last word of the URL
    local_dir=$(basename "$url" .git)

    echo "Adding subtree for URL: $url"
    git subtree add --prefix "$local_dir" "$url" "$REMOTE_BRANCH" --squash
    if [ $? -ne 0 ]; then
        echo "Error: Failed to add subtree for URL: $url"
    else
        echo "Subtree added successfully for URL: $url"
    fi
done < "$URLS_FILE"
