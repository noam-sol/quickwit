#!/bin/bash

set -e

FUNCTION_NAME=quickwit-searcher

# Check if we're in the root directory by looking for the 'distribution' directory
if [ ! -d "distribution" ]; then
    echo "Error: run this script from root dir"
    exit 1
fi

docker build -f distribution/lambda/builder.Dockerfile -t quickwit-lambda-builder --ssh default --progress=plain .
mkdir -p lambda-out/
docker run -v .:/code -it quickwit-lambda-builder sh -c "cp /lambda-out/boostrap.zip /code/lambda-out/boostrap.zip"

if [[ "$1" == "--deploy" ]]; then
    echo "Updating lambda for dev profile"
    AWS_PROFILE=dev aws lambda update-function-code \
      --function-name $FUNCTION_NAME \
      --zip-file fileb://$(pwd)/lambda-out/boostrap.zip \
      --no-cli-pager
else
    echo "Build at lambda-out/bootstrap.zip. Not deploying (use --deploy to deploy to dev profile)."
fi
