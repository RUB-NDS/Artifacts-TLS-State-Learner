#!/bin/bash

echo "=== Experiment E3: Dataset State Machine Analysis ==="
echo

echo
echo "(AE Script - E3) This experiment analyzes state machines from our dataset to demonstrate the variety of issues found."
echo "(AE Script - E3) We will analyze four representative state machines that exhibit different types of problems."
echo "(AE Script - E3) This experiment supports our claim C3 by showing examples for state machine issues we discuss in our paper."
echo
echo "(AE Script - E3) In particular, we inspect examples showing"
echo "(AE Script - E3) 1) A NetScaler state machine accepting two ClientHello messages"
echo "(AE Script - E3) 2) A state machine accepting unsolicited client certificates"
echo "(AE Script - E3) 3) A state machine showing behavioral differences for padding oracle test vectors"
echo "(AE Script - E3) Press Enter to begin the analysis."
read -r

# State Machine 1: completed-59.xml
echo
echo "(AE Script - E3) Analyzing state machine completed-59.xml..."
echo

docker run -it --rm \
    -v "$(pwd):/workspace" \
    state-machine-analysis-tool \
    -c analyze \
    -f "/workspace/experiment_dataset/Dataset/Complete State Machines/completed-59.xml"

echo
echo "(AE Script - E3) Analysis of completed-59.xml:"
echo "(AE Script - E3) This is one of the NetScaler state machines discussed in our paper."
echo "(AE Script - E3) It shows an issue similar to the old OpenSSL version analyzed in E2 allowing multiple ClientHellos."
echo "(AE Script - E3) Again, we can trace paths with two ClientHellos leading to a completed Handshake. Press Enter to trace the path."
read -r

docker run -it --rm \
    -v "$(pwd):/workspace" \
    state-machine-analysis-tool \
    -a \
    -c 'sq ID-ClientHelloWord{suite=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},ID-ClientHelloWord{suite=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},ClientKeyExchange,ChangeCipherSpecWord{},FinishedWord{}' \
    -f "/workspace/experiment_dataset/Dataset/Complete State Machines/completed-59.xml"

echo
echo "(AE Script - E3) Here, we simulate a query sending two ClientHellos followed by benign handshake messages."
echo "(AE Script - E3) Note that both for the ClientHello sent in 1. and 2., the server sends its full Server Hello flight."
echo "(AE Script - E3) Finally, after we send our Finished in 5., the server accepts the handshake by sending a Finished of its own."
echo "(AE Script - E3) Press Enter to continue to the next analysis."
read -r

# State Machine 2: completed-331.xml
echo
echo "(AE Script - E3) Analyzing state machine completed-331.xml..."
echo

docker run -it --rm \
    -v "$(pwd):/workspace" \
    state-machine-analysis-tool \
    -c analyze \
    -f "/workspace/experiment_dataset/Dataset/Complete State Machines/completed-331.xml"

echo
echo "(AE Script - E3) Analysis of completed-331.xml:"
echo "(AE Script - E3) This state machine exhibits two issues:"
echo "(AE Script - E3)   1. Accepts unexpected Certificate messages after ClientHello - violating the RFC as described in E2"
echo "(AE Script - E3)   2. HTTP data is simply ignored instead of rejected when sent in various states of an uncompleted handshake."
echo "(AE Script - E3) Subsequently, we again trace a handshake including the unexpected certificate."
echo "(AE Script - E3) Press Enter to trace the message path."
read -r

docker run -it --rm \
    -v "$(pwd):/workspace" \
    state-machine-analysis-tool \
    -a \
    -c 'sq ID-ClientHelloWord{suite=TLS_DHE_RSA_WITH_AES_128_CBC_SHA},GenericMessageWord{message=CERTIFICATE},ClientKeyExchange,ChangeCipherSpecWord{},FinishedWord{}' \
    -f "/workspace/experiment_dataset/Dataset/Complete State Machines/completed-331.xml"

echo
echo "(AE Script - E3) Here, we simulate a query sending a Certificate message prior to the ClientKeyExchange."
echo "(AE Script - E3) Note that the server does not include a CertificateRequest in its response to our ClientHello."
echo "(AE Script - E3) Still, we can proceed to send the regular handshake messages after the Certificate."
echo "(AE Script - E3) Finally, the server accepts the handshake by sending a Finished in response to our Finished."
echo "(AE Script - E3) Press Enter to continue to the next analysis."
read -r

# State Machine 3: completed-1280.xml
echo
echo "(AE Script - E3) Analyzing state machine completed-1280.xml..."
echo

docker run -it --rm \
    -v "$(pwd):/workspace" \
    state-machine-analysis-tool \
    -c analyze \
    -f "/workspace/experiment_dataset/Dataset/Complete State Machines/completed-1280.xml"

echo
echo "(AE Script - E3) Analysis of completed-1280.xml:"
echo "(AE Script - E3) This state machine exhibit distinct behavior patterns for different padding oracle test vectors."
echo "(AE Script - E3) For some vectors, it does not send an alert before closing the connection."
echo "(AE Script - E3) This state machine further accepts duplicate ClientHello messages during the handshake."
echo "(AE Script - E3) This is the end of E3. Press Enter to close."
read -r
