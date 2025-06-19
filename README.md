# Artifcats Repository

This repository contains the artifact for our USENIX Security '25 paper 'Towards Internet-Based State
Learning of TLS State Machines'. This repository is primarily intended to be used for the artifact evaluation before the final version of the artifact gets published to Zenodo. Our datasets are already available on Zenodo at https://zenodo.org/records/15520933.

## Repository Structure
### setup.sh
Setup script that builds Docker images, downloads the dataset from Zenodo, and runs basic functionality tests. The script further asks the user if long-running experiments form Experiment E1 and E2 shall be run in advance. These experiments are expected to take around 5 hours (E1) and 10 minutes (E2).

### dockerfiles/
Docker configurations for building containerized environments:
- OpenSSL 3.4.0 and OpenSSL 1.0.1j with the state learner tool
- State Machine Analysis Tool container

### experiments/
Experiment scripts demonstrating the tool's capabilities:
- `E1.sh`: State learning and analysis for OpenSSL 3.4.0 (modern, correctly-behaving implementation)
- `E2.sh`: Vulnerability detection in OpenSSL 1.0.1j (demonstrates issues similar to NetScaler findings)
- `E3.sh`: Analysis of anonymized state machines from the dataset showing various issues

### source_code/
Contains the Java source code of our tool. The source code is also used as part of the docker build steps to build the executable Java jar files using Maven.

## Setup

### Installation

1. Install Docker following the instructions at https://docs.docker.com/get-started/get-docker/
   - Configure permissions so your user can run `docker build` and `docker run`

2. Clone this repository and enter the directory:
```bash
git clone "https://github.com/RUB-NDS/Artifacts-TLS-State-Learner"
cd Artifacts-TLS-State-Learner
```

3. Run the setup script from the root directory:
```bash
./setup.sh
```

The setup script performs the following steps:
- Builds three Docker images:
  - OpenSSL 3.4.0 with state learner tool
  - OpenSSL 1.0.1j with state learner tool  
  - State Machine Analysis Tool container
- Downloads our dataset from Zenodo
- Extracts the dataset to `experiment_dataset/`
- Creates output directories for experiments
- Executes a basic functionality test
- Asks if you want to run the long computational steps from E1 (5 hours) and E2 (10 minutes) immediately

You can skip the last step and run the computational steps later as part of the experiments.

### Basic Test

The basic test is automatically executed as part of `setup.sh`. It runs the OpenSSL 3.4.0 container with minimal parameters to quickly verify functionality:

1. Runs our tool to extract a basic state machine using Docker. The Docker container will open tmux with two panes showing OpenSSL on the left and our tool on the right. This test is expected to finish within 5 minutes.
2. Results are written to: `experiment_outputs/Basic_Test/alphabet-1/`
3. Verifies creation of three files:
   - `OpenSSL3.4.0.xml` - The state machine in XML format
   - `OpenSSL3.4.0_short.pdf` - A visualization of the state machine
   - `OpenSSL3.4.0_short.dot` - Analysis details in DOT format
4. Checks that the DOT file indicates successful analysis

Expected output includes messages confirming successful Docker builds, dataset extraction, and verification that all expected files were created.

## Experiments

### E1: Full execution for OpenSSL 3.4.0 
**Time:** 10 human-minutes + 5 compute-hours

This experiment demonstrates state learning and analysis for a modern, correctly-behaving TLS implementation.

**Preparation:** Ensure Docker images are built via `setup.sh`. If the 5-hour computational step was not run during setup, `E1.sh` will execute it.

**Execution:** Run `./experiments/E1.sh` from the repository directory. 

The script will:
- Check if the state machine already exists from setup
- If not, run the 5-hour learning process
- Execute the automated analysis
- Demonstrate tracing through the state machine with duplicate ClientHellos and unexpected certificates

**Expected Results:** 
- The automated analysis should report no issues beyond Internal Error alerts
- Correct rejection of duplicate ClientHello with Unexpected Message alert
- Proper rejection of unsolicited client certificates
- A simplified visualization of the obtained state machine at `experiment_outputs/E1/alphabet-13/OpenSSL3.4.0_short.pdf`

### E2: Illustrating issue detection based on OpenSSL 1.0.1j
**Time:** 10 human-minutes + 10 compute-minutes

This experiment demonstrates the automated detection of state machine vulnerabilities in an older OpenSSL version. The issue is similar to the NetScaler real-world finding presented in the paper.

**Preparation:** Ensure Docker images are built via `setup.sh`. If the 10-minute computational step was not run during setup, `E2.sh` will execute it.

**Execution:** Run `./experiments/E2.sh` from the repository directory.

The script will:
- Check if the state machine already exists from setup
- If not, run the 10-minute learning process (limited to the first alphabet)
- Execute the automated analysis
- Demonstrate the vulnerability by tracing duplicate ClientHellos
- Show complete invalid handshake paths

**Expected Results:**
- Invalid message paths with duplicate ClientHellos that complete the handshake
- Illegal inputs (like CCS after handshake) that do not trigger an error
- Demonstration of duplicate ClientHellos incorrectly receiving ServerHello responses twice
- A simplified visualization at `experiment_outputs/E2/alphabet-1/OpenSSL1.0.1j_short.pdf`

### E3: Inspecting key findings from our dataset
**Time:** 15 human-minutes

This experiment analyzes representative state machines from our dataset to demonstrate selected issues we observed.

**Preparation:** Ensure Docker images are built and dataset is extracted via `setup.sh`.

**Execution:** Run `./experiments/E3.sh` from the repository directory.

The script analyzes three state machines:
- `completed-59.xml` - A NetScaler state machine which accepts duplicated ClientHello messages
- `completed-331.xml` - State machine accepting unsolicited certificates
- `completed-1280.xml` - State machine exhibiting deviating behavior for multiple padding oracle test vectors

**Expected Results:**
- NetScaler accepting duplicate ClientHellos (similar to E2)
- Improper certificate handling allowing unauthorized certificates
- Padding oracle vulnerabilities with behavioral differences for different padding types
- Each analysis includes interactive traces showing the specific vulnerability paths
- The variety of issues found supports the prevalence of state machine bugs in real-world deployments
