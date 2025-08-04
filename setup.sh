#!/bin/bash

# Exit on any error
set -e

echo "=== Artifact Evaluation - Preparation ==="
echo
echo "This script will build docker images and attempt to perform a basic test by running a docker container. This docker container will run tmux with two panes showing OpenSSL on the left and our tool on the right."
echo "Press Enter to begin the setup."
read -r

# Function to check if command was successful
check_status() {
    if [ $? -ne 0 ]; then
        echo "Error: $1 failed. Aborting setup."
        exit 1
    fi
}

# Step 1: Download and extract source code
echo "Step 1: Downloading source code from Zenodo..."
echo

if [ -f "source_code.zip" ]; then
    echo "Source code zip already exists, skipping download"
else
    if command -v wget &> /dev/null; then
        echo "Using wget to download source code..."
        wget -O source_code.zip "https://zenodo.org/records/15520933/files/source_code.zip?download=1"
        check_status "Source code download with wget"
    elif command -v curl &> /dev/null; then
        echo "Using curl to download source code..."
        curl -L -o source_code.zip "https://zenodo.org/records/15520933/files/source_code.zip?download=1"
        check_status "Source code download with curl"
    else
        echo "Error: Neither wget nor curl is available. Please install one of them."
        exit 1
    fi
fi

echo "✓ Source code downloaded successfully"
echo

# Extract source code
echo "Extracting source code..."
if ! command -v unzip &> /dev/null; then
    echo "Error: unzip is not installed. Please install it and run the script again."
    exit 1
fi

unzip -q -o source_code.zip -d source_code
check_status "Extracting source code"
echo "✓ Source code extracted to source_code directory"
echo

# Step 2: Build both Docker images
echo "Step 2: Building Docker images..."
echo

echo "Building OpenSSL 3.4.0 Docker image..."
docker build -f dockerfiles/Dockerfile-OpenSSL-34-Java -t openssl3-4-0-tls-learner .
check_status "OpenSSL 3.4.0 Docker build"
echo "✓ OpenSSL 3.4 image built successfully"
echo

echo "Building OpenSSL 1.0.1j Docker image..."
docker build -f dockerfiles/Dockerfile-OpenSSL-101j-Java -t openssl1-0-1j-tls-learner .
check_status "OpenSSL 1.0.1j Docker build"
echo "✓ OpenSSL 1.0.1j image built successfully"
echo

echo "Building State Machine Analysis Tool Docker image..."
docker build -f dockerfiles/Dockerfile-Analysis-Tool -t state-machine-analysis-tool .
check_status "State Machine Analysis Tool Docker build"
echo "✓ State Machine Analysis Tool image built successfully"
echo

echo "Step 3: Downloading dataset from Zenodo..."
echo

if [ -f "dataset.zip" ]; then
    echo "Dataset already exists, skipping download"
else
    if command -v wget &> /dev/null; then
        echo "Using wget to download dataset..."
        wget -O dataset.zip "https://zenodo.org/records/15520933/files/dataset.zip?download=1"
        check_status "Dataset download with wget"
    elif command -v curl &> /dev/null; then
        echo "Using curl to download dataset..."
        curl -L -o dataset.zip "https://zenodo.org/records/15520933/files/dataset.zip?download=1"
        check_status "Dataset download with curl"
    else
        echo "Error: Neither wget nor curl is available. Please install one of them."
        exit 1
    fi
fi

echo "✓ Dataset downloaded successfully"
echo

# Step 4: Extract dataset
echo "Step 4: Extracting dataset..."
echo

# Check if unzip is available
if ! command -v unzip &> /dev/null; then
    echo "Error: unzip is not installed. Please install it and run the script again."
    exit 1
fi

# Create experiment_dataset directory and extract
mkdir -p experiment_dataset
check_status "Creating experiment_dataset directory"

unzip -q -o dataset.zip -d experiment_dataset
check_status "Extracting dataset"

echo "✓ Dataset extracted to experiment_dataset"
echo

# Step 5: Create experiment output directories
echo "Step 5: Creating experiment output directories..."
echo

mkdir -p experiment_outputs/E1
check_status "Creating E1 directory"

mkdir -p experiment_outputs/E2
check_status "Creating E2 directory"

mkdir -p experiment_outputs/E3
check_status "Creating E3 directory"

mkdir -p experiment_outputs/Basic_Test
check_status "Creating Basic_Test directory"

echo "✓ Created experiment_outputs directory structure"
echo

echo "Step 6: Run basic test..."
echo

docker run -it --rm \
    -v "$(pwd)/experiment_outputs/Basic_Test:/output" \
    openssl3-4-0-tls-learner \
    -queries 1 \
    -alphabetLimit 1 \
    -implementationName OpenSSL3.4.0

echo
echo "=== Verifying basic test results ==="
echo

# Check basic test files
BASIC_XML="experiment_outputs/Basic_Test/alphabet-1/OpenSSL3.4.0.xml"
BASIC_PDF="experiment_outputs/Basic_Test/alphabet-1/OpenSSL3.4.0_short.pdf"
BASIC_DOT="experiment_outputs/Basic_Test/alphabet-1/OpenSSL3.4.0_short.dot"

# Check XML file
if [ -f "$BASIC_XML" ]; then
    echo "✓ Basic test did yield a state machine XML"
else
    echo "✗ Basic test failed to yield a state machine XML"
    echo "Basic test failed - aborting"
    exit 1
fi

# Check PDF file
if [ -f "$BASIC_PDF" ]; then
    echo "✓ Basic test did yield a PDF visualizing the state machine"
else
    echo "✗ Basic test failed to yield a PDF visualizing the state machine"
    echo "Basic test failed - aborting"
    exit 1
fi

# Check DOT file and its contents
if [ -f "$BASIC_DOT" ]; then
    echo "✓ Basic test did yield a .dot file with analysis details"
    
    if grep -q 'RSAID-ClientHello|SH,CERT,SHD,|UP' "$BASIC_DOT"; then
        echo "✓ Found basic transition for TLS 1.2 ClientHello in dot file"
    else
        echo "✗ Missing RSAID-ClientHello|SH,CERT,SHD,|UP in DOT file"
        echo "Basic test failed - automated analysis error"
        exit 1
    fi
    
    if grep -q 'Tls13ClientHello|SH,CCS,EEM,CERT,CV,FIN,|UP' "$BASIC_DOT"; then
        echo "✓ Found basic transition for TLS 1.3 ClientHello in dot file"
    else
        echo "✗ Missing Tls13ClientHello|SH,CCS,EEM,CERT,CV,FIN,|UP in DOT file"
        echo "Basic test failed - automated analysis error"
        exit 1
    fi
    
    if grep -q 'Finished|CCS,FIN,|UP' "$BASIC_DOT"; then
        echo "✓ Found TLS 1.2 Finished message in dot file"
    else
        echo "✗ Missing Finished|CCS,FIN,|UP in DOT file"
        echo "Basic test failed - automated analysis error"
        exit 1
    fi
    
    if grep -q 'Finished|ST,ST,|UP' "$BASIC_DOT"; then
        echo "✓ Found TLS 1.3 Finished message in dot file"
    else
        echo "✗ Missing Finished|ST,ST,|UP in DOT file"
        echo "Basic test failed - automated analysis error"
        exit 1
    fi
    
    echo "✓ Automated analysis appears to work"
else
    echo "✗ Basic test failed to yield a .dot file with analyis details"
    echo "Basic test failed - aborting"
    exit 1
fi

echo
echo "=== Basic test completed successfully! ==="
echo

read -p "Experiments E1 and E2 require some computation time (~5 hours for E1 and ~10 minutes for E2). Do you want this script to run the computational part of these experiments now? Otherwise, you can run them as part of the experiments. (y/n): " run_experiments
echo

if [ "$run_experiments" = "y" ] || [ "$run_experiments" = "Y" ]; then
    echo "=== Starting experiments ==="
    echo
    echo "Running OpenSSL 3.4 experiment (E1)..."
    echo "Note: This is expected to take 5 hours."
    echo
    
    docker run -it --rm \
        -v "$(pwd)/experiment_outputs/E1:/output" \
        openssl3-4-0-tls-learner \
        -queries 20000 \
        -implementationName OpenSSL3.4.0
    
    echo
    echo "Running OpenSSL 1.0.1j experiment (E2)..."
    echo "Note: This is expected to take 10 minutes."
    echo
    
    docker run -it --rm \
        -v "$(pwd)/experiment_outputs/E2:/output" \
        openssl1-0-1j-tls-learner \
        -queries 20000 \
        -implementationName OpenSSL1.0.1j \
        -alphabetLimit 1
    
    echo
    echo "=== Checking experiment results ==="
    echo
    
    # Check E1 results (OpenSSL 3.4.0)
    E1_XML="experiment_outputs/E1/alphabet-13/OpenSSL3.4.0.xml"
    E1_PDF="experiment_outputs/E1/alphabet-13/OpenSSL3.4.0_short.pdf"
    
    if [ -f "$E1_XML" ]; then
        echo "✓ State Machine OpenSSL 3.4.0 found"
    else
        echo "✗ State Machine OpenSSL 3.4.0 NOT found at $E1_XML"
    fi
    
    if [ -f "$E1_PDF" ]; then
        echo "✓ State Machine Visualization OpenSSL 3.4.0 found"
    else
        echo "✗ State Machine Visualization OpenSSL 3.4.0 NOT found at $E1_PDF"
    fi
    
    # Check E2 results (OpenSSL 1.0.1j)
    E2_XML="experiment_outputs/E2/alphabet-1/OpenSSL1.0.1j.xml"
    E2_PDF="experiment_outputs/E2/alphabet-1/OpenSSL1.0.1j_short.pdf"
    
    if [ -f "$E2_XML" ]; then
        echo "✓ State Machine OpenSSL 1.0.1j found"
    else
        echo "✗ State Machine OpenSSL 1.0.1j NOT found at $E2_XML"
    fi
    
    if [ -f "$E2_PDF" ]; then
        echo "✓ State Machine Visualization OpenSSL 1.0.1j found"
    else
        echo "✗ State Machine Visualization OpenSSL 1.0.1j NOT found at $E2_PDF"
    fi
    
    # Check if all files exist
    if [ -f "$E1_XML" ] && [ -f "$E1_PDF" ] && [ -f "$E2_XML" ] && [ -f "$E2_PDF" ]; then
        echo
        echo "=== Computational steps of experiments completed successfully! ==="
        echo "You can resume with the experiment shell scripts in experiments/"
    else
        echo
        echo "=== Computational steps of experiments did not yield expected files ==="
        echo "Please see above for missing output files"
    fi
else
    echo "=== Setup Complete ==="
    echo "To run the experiments, see experiments/"
fi
