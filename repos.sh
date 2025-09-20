#!/bin/bash
# Show all repositories, tags and image sizes from a Docker Registry

REGISTRY_URL="http://192.168.68.64:8080"

# Get all repositories
repos=$(curl -s "${REGISTRY_URL}/v2/_catalog" | jq -r '.repositories[]')

echo "📦 Docker Registry Tree:"
for repo in $repos; do
    echo "├── $repo"
    # Get tags for this repo
    tags=$(curl -s "${REGISTRY_URL}/v2/${repo}/tags/list" | jq -r '.tags[]?' 2>/dev/null)
    if [ -n "$tags" ]; then
        for tag in $tags; do
            # Fetch manifest for this tag (schema v2)
            manifest=$(curl -s -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
                "${REGISTRY_URL}/v2/${repo}/manifests/${tag}")

            # Calculate total size (sum of all layers)
            size=$(echo "$manifest" | jq '[.layers[].size] | add' 2>/dev/null)
            if [ -n "$size" ] && [ "$size" != "null" ]; then
                # Convert to MB
                size_mb=$(awk "BEGIN {printf \"%.2f\", $size/1024/1024}")
                echo "│   └── ${tag}  (${size_mb} MB)"
            else
                echo "│   └── ${tag}  (size unknown)"
            fi
        done
    else
        echo "│   └── <no tags>"
    fi
done
