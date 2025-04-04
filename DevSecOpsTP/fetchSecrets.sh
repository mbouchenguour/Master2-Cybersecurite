#!/bin/bash

# Ensure that the required environment variables are set
if [ -z "$INFISICAL_MACHINE_CLIENT_ID" ] || [ -z "$INFISICAL_MACHINE_CLIENT_SECRET" ] || [ -z "$PROJECT_ID" ] || [ -z "$INFISICAL_SECRET_ENV" ]; then
  echo "Error: One or more required environment variables are not set."
  echo "Please set INFISICAL_MACHINE_CLIENT_ID, INFISICAL_MACHINE_CLIENT_SECRET, PROJECT_ID, and INFISICAL_SECRET_ENV."
  exit 1
fi

# Install the Infisical CLI if not already installed
if ! command -v infisical &> /dev/null; then
  echo "Infisical CLI not found. Installing..."

  # Add Infisical repository and install the CLI
  curl -1sLf 'https://dl.cloudsmith.io/public/infisical/infisical-cli/setup.rpm.sh' | sudo -E bash
  sudo yum install -y infisical

  # Verify installation
  if command -v infisical &> /dev/null; then
    echo "Infisical CLI installed successfully."
  else
    echo "Failed to install Infisical CLI. Please check the logs."
    exit 1
  fi
fi

# Obtain the Infisical token using the provided client ID and secret
INFISICAL_TOKEN=$(infisical login --method=universal-auth \
  --client-id="$INFISICAL_MACHINE_CLIENT_ID" \
  --client-secret="$INFISICAL_MACHINE_CLIENT_SECRET" \
  --silent --plain \
  --domain=https://eu.infisical.com)

# Check if the token was obtained successfully
if [ -z "$INFISICAL_TOKEN" ]; then
  echo "Error: Failed to obtain the Infisical token."
  exit 1
fi

# Export all secrets from the specified environment to the .env file
infisical export \
  --env="$INFISICAL_SECRET_ENV" \
  --projectId="$PROJECT_ID" \
  --token="$INFISICAL_TOKEN" \
  --domain=https://eu.infisical.com > .env

echo "Successfully updated the .env file with secrets from Infisical."
