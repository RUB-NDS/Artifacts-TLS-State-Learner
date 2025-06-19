#!/bin/bash

echo "=== Experiment E2: OpenSSL 1.0.1j Analysis ==="
echo

echo
echo "(AE Script - E2) This experiment will first derive a state machine for OpenSSL 1.0.1j using the docker image unless this was already done during the setup."
echo "(AE Script - E2) Subsequently, this experiment will again use the CLI tool to navigate through the obtained state machine."
echo "(AE Script - E2) For this version of OpenSSL, we expect our tool to identify issues. This experiment hence is intended to support our claims C1 and C2."
echo

# Expected files from setup.sh
E2_XML="experiment_outputs/E2/alphabet-1/OpenSSL1.0.1j.xml"
E2_PDF="experiment_outputs/E2/alphabet-1/OpenSSL1.0.1j_short.pdf"

# Check if expected files already exist
if [ -f "$E2_XML" ] && [ -f "$E2_PDF" ]; then
    echo "(AE Script - E2) ✓ State machine files already exist."
    echo "(AE Script - E2) Press Enter to proceed with the inspection of the state machine."
    read -r
else
    echo "(AE Script - E2) The state machine files were not found in experiment_outputs/E2/alphabet-1/"
    echo "(AE Script - E2) Press Enter to proceed to extract the state machine for OpenSSL 1.0.1j. This is expected to take about 10 minutes."
    read -r
    
    # Run the OpenSSL 1.0.1j container to generate state machine
    docker run -it --rm \
        -v "$(pwd)/experiment_outputs/E2:/output" \
        openssl1-0-1j-tls-learner \
        -queries 20000 \
        -implementationName OpenSSL1.0.1j \
        -alphabetLimit 1
    
    # Verify files were created
    if [ ! -f "$E2_XML" ]; then
        echo "Error: State machine XML file was not created"
        exit 1
    fi
    
    if [ ! -f "$E2_PDF" ]; then
        echo "Error: State machine PDF file was not created"
        exit 1
    fi
    
    echo
    echo "(AE Script - E2) ✓ State machine extracted successfully."
    echo "Press Enter to proceed with the inspection of the state machine."
    read -r
fi

echo
echo "(AE Script - E2) Running state machine analyzer..."
echo

# Run the analyzer container
docker run -it --rm \
    -v "$(pwd):/workspace" \
    state-machine-analysis-tool \
    -c analyze \
    -f /workspace/$E2_XML

echo
echo "(AE Script - E2) This is the output of the 'analyze' command which executes the automated analysis."
echo "(AE Script - E2) Unlike E1, this version shows several issues:"
echo "(AE Script - E2) - Invalid message paths with duplicate ClientHello messages that still complete the handshake"
echo "(AE Script - E2) - Illegal inputs (like CCS after handshake) that change state but don't reach an error state"
echo "(AE Script - E2) For comparison with the correct behavior shown in E1, we will now trace through the state machine."
echo "(AE Script - E2) Press Enter to proceed by tracing duplicate ClientHello messages."
read -r

docker run -it --rm \
    -v "$(pwd):/workspace" \
    state-machine-analysis-tool \
    -c 'sq ID-ClientHelloWord{suite=TLS_RSA_WITH_IDEA_CBC_SHA},ID-ClientHelloWord{suite=TLS_RSA_WITH_IDEA_CBC_SHA}' \
    -f /workspace/$E2_XML

echo
echo "(AE Script - E2) This is the output of the sq (simulate query) command."
echo "(AE Script - E2) It should indicate a message sequence consisting of two ClientHello messages."
echo "(AE Script - E2) Unlike the correct behavior in E1, both ClientHellos receive a ServerHello response."
echo "(AE Script - E2) The second ClientHello should have been rejected with an Unexpected Message alert."
echo "(AE Script - E2) Instead, OpenSSL 1.0.1j accepts this duplicate ClientHello and continues the handshake."
echo "(AE Script - E2) Note that our learner resets the session transcript for each new Client Hello. Being able to conclude the handshake means the server also cleared the transcript and discarded the first Client Hello."
echo "(AE Script - E2) Press Enter to see the complete invalid handshake path."
read -r

docker run -it --rm \
    -v "$(pwd):/workspace" \
    state-machine-analysis-tool \
    -c 'sq ID-ClientHelloWord{suite=TLS_RSA_WITH_IDEA_CBC_SHA},ID-ClientHelloWord{suite=TLS_RSA_WITH_IDEA_CBC_SHA},ClientKeyExchange,ChangeCipherSpecWord{},FinishedWord{}' \
    -f /workspace/$E2_XML

echo
echo "(AE Script - E2) This trace shows the complete invalid handshake path."
echo "(AE Script - E2) After the duplicate ClientHello, the client can still complete the handshake normally."
echo "(AE Script - E2) This violates the TLS specification and represents a state machine bug in OpenSSL 1.0.1j."
echo "(AE Script - E2) You can view experiment_outputs/E2/alphabet-1/OpenSSL1.0.1j_short.pdf for a visualization with invalid states highlighted."
echo "(AE Script - E2) This is the end of E2. Press Enter to close."
read -r
