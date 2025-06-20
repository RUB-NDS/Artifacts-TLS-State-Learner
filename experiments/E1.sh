#!/bin/bash

echo "=== Experiment E1: OpenSSL 3.4.0 Analysis ==="
echo

echo
echo "(AE Script - E1) This experiment will first derive a state machine for OpenSSL 3.4.0 using the docker image unless this was already done during the setup."
echo "(AE Script - E1) Subsequently, this experiment is using our CLI tool to illustrate some of the findings."
echo "(AE Script - E1) Note that the CLI tool is technically not required to prove our claims as the state machine extraction and analysis are integrated into the state learner itself."
echo "(AE Script - E1) We will hence only discuss features of the CLI tool which help to point out flaws in the state machines obtained in the experiments."
echo "(AE Script - E1) In particular, the CLI tool will be used to re-run our automated analysis. This experiment is intended to support our claims C1 and C2."


# Expected files from setup.sh
E1_XML="experiment_outputs/E1/alphabet-13/OpenSSL3.4.0.xml"
E1_PDF="experiment_outputs/E1/alphabet-13/OpenSSL3.4.0_short.pdf"

# Check if expected files already exist
if [ -f "$E1_XML" ] && [ -f "$E1_PDF" ]; then
    echo "(AE Script - E1) ✓ State machine files already exist."
    echo "(AE Script - E1) Press Enter to proceed with the inspection of the state machine."
    read -r
else
    echo "(AE Script - E1) The state machine files were not found in experiment_outputs/E1/alphabet-13/"
    echo "(AE Script - E1) Press Enter to proceed to extract the state machine for OpenSSL 3.4.0. This is expected to take about 5 hours."
    read -r
    
    # Run the OpenSSL 3.4.0 container to generate state machine
    docker run -it --rm \
        -v "$(pwd)/experiment_outputs/E1:/output" \
        openssl3-4-0-tls-learner \
        -queries 20000 \
        -implementationName OpenSSL3.4.0
    
    # Verify files were created
    if [ ! -f "$E1_XML" ]; then
        echo "Error: State machine XML file was not created"
        exit 1
    fi
    
    if [ ! -f "$E1_PDF" ]; then
        echo "Error: State machine PDF file was not created"
        exit 1
    fi
    
    echo

    echo "(AE Script - E1) ✓ State machine extracted successfully."
    echo "Press Enter to proceed with the inspection of the state machine."
    read -r
fi

echo
echo "Running state machine analyzer..."
echo

# Run chain of analyzer containers
docker run -it --rm \
    -v "$(pwd):/workspace" \
    state-machine-analysis-tool \
    -c analyze \
    -f /workspace/$E1_XML

echo
echo "(AE Script - E1) This is the output of the CLI tool's 'analyze' command which executes our automated analysis."
echo "(AE Script - E1) For this version of OpenSSL, it should indicate no issues beyond Internal Error alerts sent in one state."
echo "(AE Script - E1) We tracked these alerts in particular as they may point towards issues in the code stack."
echo "(AE Script - E1) For comparison with other state machines shown in E2 and E3, we will now iterate through the state machine."
echo "(AE Script - E1) Press Enter to proceed by tracing duplicate ClientHello messages."
read -r

docker run -it --rm \
    -v "$(pwd):/workspace" \
    state-machine-analysis-tool \
    -c 'sq ID-ClientHelloWord{suite=TLS_RSA_WITH_AES_128_CBC_SHA},ID-ClientHelloWord{suite=TLS_RSA_WITH_AES_128_CBC_SHA}' \
    -f /workspace/$E1_XML

echo
echo "(AE Script - E1) This is the output of the sq (simulate query) command."
echo "(AE Script - E1) It should indicate a message sequence consisting of two ClientHello messages."
echo "(AE Script - E1) For the first message, OpenSSL's response should consist of a ServerHello, Certificate, and ServerHelloDone."
echo "(AE Script - E1) The second ClientHello should be rejected with an Unexpected Message alert and the socket state should be 'CLOSED'."
echo "(AE Script - E1) This would be the correct way to reject this misplaced additional ClientHello."
echo "(AE Script - E1) Press Enter to proceed by tracing a path with an unexpected client certificate."
read -r

docker run -it --rm \
    -v "$(pwd):/workspace" \
    state-machine-analysis-tool \
    -c 'sq ID-ClientHelloWord{suite=TLS_RSA_WITH_AES_128_CBC_SHA},GenericMessageWord{message=CERTIFICATE}' \
    -f /workspace/$E1_XML


echo
echo "(AE Script - E1) In this call to the sq command, we trace a path consisting of a ClientHello and a Certificate."
echo "(AE Script - E1) Note that the server did not send a CertificateRequest in response to the ClientHello."
echo "(AE Script - E1) As noted in the RFC, the client is thus not allowed to send a Certificate message:"
echo "(AE Script - E1) 'This message is only sent if the server requests a certificate.' - RFC 5246 7.4.6.  Client Certificate"
echo "(AE Script - E1) The output should indicate that OpenSSL correctly rejected this message with an Unexpected Message alert again."
echo "(AE Script - E1) This is the end of E1. You can take a look at experiment_outputs/E1/alphabet-13/OpenSSL3.4.0_short.pdf for a simplified visualization of the state machine."
echo "(AE Script - E1) Press Enter to close."
read -r
