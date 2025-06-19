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


## Running the experiments
- Build the necessary docker images using setup.sh first.
- Use `./experiments/E1.sh` while in the main repository directory to extract a state machine of OpenSSL 3.4.0 (unless this was already done as part of the setup). Subsequently, the script will run our CLI tool to re-run our automated analysis and to illustrate some aspects of the obtained state machine. You should further find a PDF providing a simplified visualization of the obtained state machine in `experiment_outputs/E1/alphabet-13/OpenSSL3.4.0_short.pdf`.
- Use `./experiments/E2.sh` to demonstrate vulnerability detection in OpenSSL 1.0.1j (unless extraction was already done during setup). The script extracts a state machine exhibiting issues similar to the NetScaler findings in our paper, runs automated analysis to detect multiple state machine vulnerabilities, and demonstrates how duplicate ClientHellos are improperly accepted. A visualization is available at `experiment_outputs/E2/alphabet-1/OpenSSL1.0.1j_short.pdf`.
- Use `./experiments/E3.sh` to analyze representative state machines from our dataset demonstrating various issues. The script examines three anonymized state machines showing: A NetScaler host accepting duplicate ClientHellos, a host accepting unsolicited certificates, and a host exhibiting a padding oracle vulnerability.
