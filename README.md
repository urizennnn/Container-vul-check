# Container Vulnerability Scanning
This is a simple go script that uses Trivy to scan a container image for vulnerabilities. It is intended to be used in a CI/CD pipeline to ensure that the container image is free of vulnerabilities before being deployed.

## Prerequisites
- Go v1.23 should be installed on the machine before running the script.

## Usage
To use the script to scan a container image, run the following command:

- create a workflow file in your repository, here is an example of a workflow file:
```yaml
name: Build and Vulnerability Check

on:
  push:
    branches:
      - master

jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2

      - name: Install Trivy
        run: |
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
          trivy --version

      - name: Build Docker Image
        run: |
          docker build -t sometelexname:${{ github.sha }} .

      - name: Install Go 
        uses: actions/setup-go@v4
        with:
          go-version: '1.23'

      - name: Build Vulnerability Checker
        run: |
          go build -o vulnerability_checker main.go

      - name: Run Vulnerability Checker
        env:
          TELEX_ENDPOINT: ${{ secrets.TELEX_ENDPOINT }}
        run: |
          ./vulnerability_checker sometelexname:${{ github.sha }} $TELEX_ENDPOINT

```
- create a secret in your repository called `TELEX_ENDPOINT` and set the value to the endpoint of the Telex API.
this should be the endpoint of the Telex API that you have deployed or any service.
