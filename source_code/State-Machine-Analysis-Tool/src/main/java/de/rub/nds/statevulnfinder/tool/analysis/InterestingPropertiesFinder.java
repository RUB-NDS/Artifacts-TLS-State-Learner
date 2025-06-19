/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.analysis;

import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.algorithm.words.ChangeCipherSpecWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.ClientHelloWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.DummyChangeCipherSpecWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextProperty;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class InterestingPropertiesFinder {

    /*
     * FATAL_ALERT_DOES_NOT_GO_TO_ERROR,
    UNKNOWN_ALERT_DESCRIPTION,
    MULTIPLE_ALERTS,
    PARTIAL_HANDSHAKE_MESSAGES_RECEIVED,
    HAS_UNNAMED_TERMINAL_STATES,
    HANDSHAKE_RECEIVED_TO_TERMINAL_STATES,
    HANDSHAKE_RECEIVED_TO_ERROR_STATE,
    DECRYPTION_RELATED_ALERT_WITHOUT_CCS,
    RESPONSE_HAS_RECORD_BUT_NO_MESSAGE
     */

    public static String findInterestingProperties(
            StateMachine stateMachine, GraphDetails graphDetails) {
        String analysisResult = "";
        analysisResult += findFatalAlertDoesNotGoToError(stateMachine, graphDetails);
        analysisResult += findUnknownAlerts(stateMachine, graphDetails);
        analysisResult += findMultipleAlerts(stateMachine, graphDetails);
        analysisResult += findPartialHandshakeMessagesReceived(stateMachine, graphDetails);
        analysisResult += findHasUnnamedTerminalState(stateMachine, graphDetails);
        analysisResult += findHandshakeRecievedToTerminalState(stateMachine, graphDetails);
        analysisResult += findHandshakeReceivedToErrorState(stateMachine, graphDetails);
        analysisResult += findResponseHasRecordButNoMessage(stateMachine);
        analysisResult += findDecryptionRelatedAlertWithoutCcs(stateMachine, graphDetails);
        return analysisResult;
    }

    public static String findFatalAlertDoesNotGoToError(
            StateMachine stateMachine, GraphDetails graphDetails) {
        String analysisResult = "";
        for (Object state : stateMachine.getMealyMachine().getStates()) {
            for (TlsWord input : stateMachine.getAlphabet()) {
                SulResponse output =
                        (SulResponse) stateMachine.getMealyMachine().getOutput(state, input);
                Object successor = stateMachine.getMealyMachine().getSuccessor(state, input);
                List<AlertMessage> alertsReceived =
                        AnalysisUtil.getMessagesFromResponse(output, AlertMessage.class);
                for (AlertMessage alert : alertsReceived) {
                    if (alert.getLevel().getValue() == AlertLevel.FATAL.getValue()
                            && !graphDetails.isErrorState(successor)
                            && !AnalysisUtil.getDummyStates(stateMachine).contains(successor)) {
                        analysisResult +=
                                "State "
                                        + state
                                        + " goes to non-error state"
                                        + successor
                                        + " for input "
                                        + input
                                        + "\n";
                    }
                }
            }
        }
        if (analysisResult.isEmpty()) {
            return "";
        } else {
            return "\nFound FATAL_ALERT_DOES_NOT_GO_TO_ERROR:\n" + analysisResult;
        }
    }

    public static String findUnknownAlerts(StateMachine stateMachine, GraphDetails graphDetails) {
        String analysisResult = "";
        for (Object state : stateMachine.getMealyMachine().getStates()) {
            for (TlsWord input : stateMachine.getAlphabet()) {
                SulResponse output =
                        (SulResponse) stateMachine.getMealyMachine().getOutput(state, input);
                List<AlertMessage> alertsReceived =
                        AnalysisUtil.getMessagesFromResponse(output, AlertMessage.class);
                for (AlertMessage alert : alertsReceived) {
                    boolean matchFound = false;
                    for (AlertDescription description : AlertDescription.values()) {
                        if (alert.getDescription().getValue() == description.getValue()) {
                            boolean levelMatchFound = false;
                            for (AlertLevel level : AlertLevel.values()) {
                                if (level.getValue() == alert.getLevel().getValue()) {
                                    levelMatchFound = true;
                                    break;
                                }
                            }
                            if (levelMatchFound) {
                                // suppress matching descr if level is unknown
                                matchFound = true;
                                break;
                            }
                        }
                    }
                    if (!matchFound) {
                        analysisResult +=
                                "From state "
                                        + state
                                        + " input "
                                        + input
                                        + " yields unknown alert value "
                                        + alert.getDescription().getValue()
                                        + " with level "
                                        + alert.getLevel().getValue()
                                        + "\n";
                    }
                }
            }
        }
        if (analysisResult.isEmpty()) {
            return "";
        } else {
            return "\nFound UNKNOWN_ALERT_DESCRIPTION:\n" + analysisResult;
        }
    }

    public static String findMultipleAlerts(StateMachine stateMachine, GraphDetails graphDetails) {
        String analysisResult = "";
        for (Object state : stateMachine.getMealyMachine().getStates()) {
            for (TlsWord input : stateMachine.getAlphabet()) {
                SulResponse output =
                        (SulResponse) stateMachine.getMealyMachine().getOutput(state, input);
                List<AlertMessage> alertsReceived =
                        AnalysisUtil.getMessagesFromResponse(output, AlertMessage.class);
                if (alertsReceived.size() > 1
                        && alertsReceived.get(1).getDescription().getValue()
                                != AlertDescription.CLOSE_NOTIFY.getValue()) {
                    analysisResult +=
                            "From state "
                                    + state
                                    + " input "
                                    + input
                                    + " yields multiple alerts ("
                                    + alertsReceived.stream()
                                            .map(AlertMessage::getDescription)
                                            .map(
                                                    description ->
                                                            AlertDescription.getAlertDescription(
                                                                    description.getValue()))
                                            .map(AlertDescription::name)
                                            .collect(Collectors.joining(","))
                                    + ")\n";
                }
            }
        }
        if (analysisResult.isEmpty()) {
            return "";
        } else {
            return "\nFound MULTIPLE_ALERTS except Other + Close Notify:\n" + analysisResult;
        }
    }

    public static String findPartialHandshakeMessagesReceived(
            StateMachine stateMachine, GraphDetails graphDetails) {
        List<List<Class<?>>> handshakeMessageFlights = new LinkedList<>();
        handshakeMessageFlights.add(
                List.of(
                        ServerHelloMessage.class,
                        CertificateMessage.class,
                        CertificateRequestMessage.class,
                        ServerHelloDoneMessage.class));
        handshakeMessageFlights.add(
                List.of(
                        ServerHelloMessage.class,
                        CertificateMessage.class,
                        ServerHelloDoneMessage.class));
        handshakeMessageFlights.add(
                List.of(
                        ServerHelloMessage.class,
                        CertificateMessage.class,
                        ServerKeyExchangeMessage.class,
                        ServerHelloDoneMessage.class));
        handshakeMessageFlights.add(
                List.of(
                        ServerHelloMessage.class,
                        CertificateMessage.class,
                        ServerKeyExchangeMessage.class,
                        CertificateRequestMessage.class,
                        ServerHelloDoneMessage.class));
        handshakeMessageFlights.add(
                List.of(
                        ServerHelloMessage.class,
                        EncryptedExtensionsMessage.class,
                        CertificateMessage.class,
                        CertificateVerifyMessage.class,
                        FinishedMessage.class));
        // SERVER_HELLO,CHANGE_CIPHER_SPEC,ENCRYPTED_EXTENSIONS,CERTIFICATE,CERTIFICATE_VERIFY,FINISHED
        handshakeMessageFlights.add(
                List.of(
                        ServerHelloMessage.class,
                        ChangeCipherSpecMessage.class,
                        EncryptedExtensionsMessage.class,
                        CertificateMessage.class,
                        CertificateVerifyMessage.class,
                        FinishedMessage.class));
        handshakeMessageFlights.add(List.of(ChangeCipherSpecMessage.class, FinishedMessage.class));
        String analysisResult = "";
        for (Object state : stateMachine.getMealyMachine().getStates()) {
            for (TlsWord input : stateMachine.getAlphabet()) {
                SulResponse output =
                        (SulResponse) stateMachine.getMealyMachine().getOutput(state, input);
                List<ProtocolMessage> handshakeMessages =
                        AnalysisUtil.getMessagesFromResponse(output, ProtocolMessage.class);
                if (handshakeMessages.isEmpty()
                        || handshakeMessages.stream().noneMatch(HandshakeMessage.class::isInstance)
                        || handshakeMessages.stream()
                                .allMatch(NewSessionTicketMessage.class::isInstance)) {
                    continue;
                }
                boolean allMessagesReceived = false;
                for (List<Class<?>> handshakeMessageFlight : handshakeMessageFlights) {
                    boolean thisFlightMatches = true;
                    for (Class<?> messageClass : handshakeMessageFlight) {
                        if (handshakeMessages.stream().noneMatch(messageClass::isInstance)) {
                            thisFlightMatches = false;
                            break;
                        }
                    }
                    if (thisFlightMatches) {
                        allMessagesReceived = true;
                        break;
                    }
                }
                boolean hasCorrectHelloRetryRequest =
                        input.getType() == TlsWordType.HRR_ENFORCING_HELLO
                                && handshakeMessages.stream()
                                        .filter(ServerHelloMessage.class::isInstance)
                                        .map(message -> (ServerHelloMessage) message)
                                        .anyMatch(message -> message.isTls13HelloRetryRequest());
                if ((handshakeMessages.size() == 1 && hasCorrectHelloRetryRequest)
                        || (handshakeMessages.size() == 2
                                && hasCorrectHelloRetryRequest
                                && handshakeMessages.get(1) instanceof ChangeCipherSpecMessage)) {
                    // check more carefully for hello retry request
                    allMessagesReceived = true;
                }
                if (!allMessagesReceived) {
                    analysisResult +=
                            "Starting in state "
                                    + state
                                    + " and sending "
                                    + input
                                    + " yields an incomplete handshake message flight ("
                                    + handshakeMessages.stream()
                                            .map(ProtocolMessage::toCompactString)
                                            .collect(Collectors.joining(","))
                                    + ")\n";
                }
            }
        }
        if (analysisResult.isEmpty()) {
            return "";
        } else {
            return "\nFound PARTIAL_HANDSHAKE_MESSAGES_RECEIVED:\n" + analysisResult;
        }
    }

    public static String findHasUnnamedTerminalState(
            StateMachine stateMachine, GraphDetails graphDetails) {
        String analysisResult = "";
        for (Object state : stateMachine.getMealyMachine().getStates()) {
            if (AnalysisUtil.isTerminalState(stateMachine, state, graphDetails.getErrorStates())
                    && !graphDetails.hasStateInfo(state)) {
                analysisResult += "State " + state + " is a terminal state but has no name\n";
            }
        }
        if (analysisResult.isEmpty()) {
            return "";
        } else {
            return "\nFound HAS_UNNAMED_TERMINAL_STATES:\n" + analysisResult;
        }
    }

    public static String findHandshakeRecievedToTerminalState(
            StateMachine stateMachine, GraphDetails graphDetails) {
        String analysisResult = "";
        for (Object state : stateMachine.getMealyMachine().getStates()) {
            for (TlsWord input : stateMachine.getAlphabet()) {
                SulResponse output =
                        (SulResponse) stateMachine.getMealyMachine().getOutput(state, input);
                Object successor = stateMachine.getMealyMachine().getSuccessor(state, input);
                List<HandshakeMessage> handshakeMessages =
                        AnalysisUtil.getMessagesFromResponse(output, HandshakeMessage.class);
                boolean notBleichenbacherPath =
                        !graphDetails.hasStateInfo(state)
                                || !graphDetails
                                        .getStateInfo(state)
                                        .getContextPropertiesWhenReached()
                                        .contains(ContextProperty.BLEICHENBACHER_PATH);
                if (!handshakeMessages.isEmpty()
                        && notBleichenbacherPath
                        && AnalysisUtil.isTerminalState(
                                stateMachine, successor, graphDetails.getErrorStates())) {
                    analysisResult +=
                            "State "
                                    + state
                                    + " can be reached with input "
                                    + input
                                    + " and yields a handshake message ("
                                    + handshakeMessages.stream()
                                            .map(HandshakeMessage::toCompactString)
                                            .collect(Collectors.joining(","))
                                    + ") but leads to a terminal state ("
                                    + successor
                                    + ")\n";
                }
            }
        }
        if (analysisResult.isEmpty()) {
            return "";
        } else {
            return "\nFound HANDSHAKE_RECEIVED_TO_TERMINAL_STATE:\n" + analysisResult;
        }
    }

    public static String findHandshakeReceivedToErrorState(
            StateMachine stateMachine, GraphDetails graphDetails) {
        String analysisResult = "";
        for (Object state : stateMachine.getMealyMachine().getStates()) {
            for (TlsWord input : stateMachine.getAlphabet()) {
                SulResponse output =
                        (SulResponse) stateMachine.getMealyMachine().getOutput(state, input);
                Object successor = stateMachine.getMealyMachine().getSuccessor(state, input);
                List<HandshakeMessage> handshakeMessages =
                        AnalysisUtil.getMessagesFromResponse(output, HandshakeMessage.class);
                if (!handshakeMessages.isEmpty()
                        && (graphDetails.isErrorState(successor)
                                || AnalysisUtil.getDummyStates(stateMachine).contains(successor))) {
                    analysisResult +=
                            "State "
                                    + state
                                    + " can be reached with input "
                                    + input
                                    + " and yields a handshake message ("
                                    + handshakeMessages.stream()
                                            .map(HandshakeMessage::toCompactString)
                                            .collect(Collectors.joining(","))
                                    + ") but leads to an error state\n";
                }
            }
        }
        if (analysisResult.isEmpty()) {
            return "";
        } else {
            return "\nFound HANDSHAKE_RECEIVED_TO_ERROR_STATE:\n" + analysisResult;
        }
    }

    public static String findResponseHasRecordButNoMessage(StateMachine stateMachine) {
        String analysisResult = "";
        for (Object state : stateMachine.getMealyMachine().getStates()) {
            for (TlsWord input : stateMachine.getAlphabet()) {
                SulResponse output =
                        (SulResponse) stateMachine.getMealyMachine().getOutput(state, input);
                boolean hasRecords =
                        output.getResponseFingerprint() != null
                                && output.getResponseFingerprint().getRecordList() != null
                                && !output.getResponseFingerprint().getRecordList().isEmpty();
                boolean hasRecordsButNoMessages =
                        hasRecords
                                && (output.getResponseFingerprint().getMessageList() == null
                                        || output.getResponseFingerprint()
                                                .getMessageList()
                                                .isEmpty());
                if (hasRecordsButNoMessages) {
                    analysisResult +=
                            "State "
                                    + state
                                    + " can be reached with input "
                                    + input
                                    + " and yields a record but no message\n";
                }
            }
        }
        if (analysisResult.isEmpty()) {
            return "";
        } else {
            return "\nFound RESPONSE_HAS_RECORD_BUT_NO_MESSAGE:\n" + analysisResult;
        }
    }

    public static String findDecryptionRelatedAlertWithoutCcs(
            StateMachine stateMachine, GraphDetails graphDetails) {
        String analysisResult = "";
        List<AlertDescription> relevantAlerts =
                List.of(
                        AlertDescription.DECRYPT_ERROR,
                        AlertDescription.DECRYPTION_FAILED_RESERVED,
                        AlertDescription.BAD_RECORD_MAC);
        for (Object state : stateMachine.getMealyMachine().getStates()) {
            boolean relevantState =
                    !AnalysisUtil.stateCanBeReachedWith(
                                    stateMachine,
                                    state,
                                    new ChangeCipherSpecWord(),
                                    new DummyChangeCipherSpecWord())
                            && (!graphDetails.hasStateInfo(state)
                                    || (!graphDetails
                                                    .getStateInfo(state)
                                                    .getContextPropertiesWhenReached()
                                                    .contains(ContextProperty.CCS_SENT)
                                            && !graphDetails
                                                    .getStateInfo(state)
                                                    .getContextPropertiesWhenReached()
                                                    .contains(ContextProperty.IS_TLS13_FLOW)));
            if (relevantState) {
                for (TlsWord input : stateMachine.getAlphabet()) {
                    SulResponse output =
                            (SulResponse) stateMachine.getMealyMachine().getOutput(state, input);
                    List<AlertMessage> alertsReceived =
                            AnalysisUtil.getMessagesFromResponse(output, AlertMessage.class);
                    for (AlertMessage alert : alertsReceived) {
                        if (relevantAlerts.contains(
                                AlertDescription.getAlertDescription(
                                        alert.getDescription().getValue()))) {
                            analysisResult +=
                                    "State "
                                            + state
                                            + " can be reached with input "
                                            + input
                                            + " and yields alert "
                                            + AlertDescription.getAlertDescription(
                                                    alert.getDescription().getValue())
                                            + "\n";
                        }
                    }
                }
            }
        }

        if (analysisResult.isEmpty()) {
            return "";
        } else {
            return "\nFound DECRYPTION_RELATED_ALERT_WITHOUT_CCS:\n" + analysisResult;
        }
    }

    public static String getStateMachineStats(
            StateMachine stateMachine, GraphDetails graphDetails) {
        List<String> statInfoList = new LinkedList<>();
        statInfoList = getNodeStats(stateMachine, graphDetails, statInfoList);
        statInfoList = getAlphabetStats(stateMachine, graphDetails, statInfoList);
        return statInfoList.stream().collect(Collectors.joining(", "));
    }

    private static List<String> getAlphabetStats(
            StateMachine stateMachine, GraphDetails graphDetails, List<String> statInfoList) {
        statInfoList.add("Alphabet[" + stateMachine.getAlphabet().size() + "]");
        int tls12Hellos = 0;
        int tls13Hellos = 0;
        boolean gotAead = false;
        boolean gotStream = false;
        boolean gotCbcBlock = false;
        boolean gotRsaKex = false;
        boolean gotDh = false;
        boolean gotDhe = false;
        boolean gotEcdh = false;
        boolean gotEcdhe = false;
        for (TlsWord word : stateMachine.getAlphabet()) {
            if (TlsWordType.effectivelyEquals(TlsWordType.TLS12_CLIENT_HELLO, word.getType())
                    && !TlsWordType.effectivelyEquals(TlsWordType.RESUMING_HELLO, word.getType())) {
                tls12Hellos++;
            } else if (TlsWordType.effectivelyEquals(
                    TlsWordType.TLS13_CLIENT_HELLO, word.getType())) {
                tls13Hellos++;
            }

            if (TlsWordType.effectivelyEquals(TlsWordType.TLS12_CLIENT_HELLO, word.getType())) {
                if (((ClientHelloWord) word).getSuite().isAEAD()) {
                    gotAead = true;
                }
                if (((ClientHelloWord) word).getSuite().name().contains("RC4")) {
                    gotStream = true;
                }
                if (((ClientHelloWord) word).getSuite().name().contains("CBC")) {
                    gotCbcBlock = true;
                }
                if (((ClientHelloWord) word).getSuite().name().contains("TLS_RSA")) {
                    gotRsaKex = true;
                }
                if (((ClientHelloWord) word).getSuite().name().contains("TLS_DH_")) {
                    gotDh = true;
                }
                if (((ClientHelloWord) word).getSuite().name().contains("_DHE_")) {
                    gotDhe = true;
                }
                if (((ClientHelloWord) word).getSuite().name().contains("ECDH_")) {
                    gotEcdh = true;
                }
                if (((ClientHelloWord) word).getSuite().name().contains("_ECDHE_")) {
                    gotEcdhe = true;
                }
            }
        }
        statInfoList.add("TLS12_HELLOS[" + tls12Hellos + "]");
        if (tls13Hellos > 0) {
            statInfoList.add("TLS13_HELLO");
        }
        if (gotAead) {
            statInfoList.add("CH_AEAD_SUPPORT");
        }
        if (gotStream) {
            statInfoList.add("CH_STREAM_SUPPORT");
        }
        if (gotCbcBlock) {
            statInfoList.add("CH_CBC_BLOCK_SUPPORT");
        }
        if (gotRsaKex) {
            statInfoList.add("CH_RSA_KEX_SUPPORT");
        }
        if (gotDh) {
            statInfoList.add("CH_DH_SUPPORT");
        }
        if (gotDhe) {
            statInfoList.add("CH_DHE_SUPPORT");
        }
        if (gotEcdh) {
            statInfoList.add("CH_ECDH_SUPPORT");
        }
        if (gotEcdhe) {
            statInfoList.add("CH_ECDHE_SUPPORT");
        }

        return statInfoList;
    }

    private static List<String> getNodeStats(
            StateMachine stateMachine, GraphDetails graphDetails, List<String> statInfoList) {
        boolean resumptionFound = false;
        boolean renegotiationFound = false;
        boolean tls13CompletedFound = false;
        boolean tls12CompletedFound = false;
        boolean certRequested = false;
        boolean noCompletedFound = false;
        boolean certRequestedAndCompleted = false;
        boolean certRequestedAndNoCompleted = false;
        boolean gotHeartbeatResponse = false;
        boolean resumptionAcceptedButTcpClosedFound = false;

        TlsWord heartbeatWord =
                stateMachine.getAlphabet().stream()
                        .filter(
                                word ->
                                        TlsWordType.effectivelyEquals(
                                                TlsWordType.HEARTBEAT, word.getType()))
                        .findFirst()
                        .orElse(null);
        for (Object state : stateMachine.getMealyMachine().getStates()) {
            if (heartbeatWord != null) {
                SulResponse heartbeatResponse =
                        (SulResponse)
                                stateMachine.getMealyMachine().getOutput(state, heartbeatWord);
                List<HeartbeatMessage> heartbeats =
                        AnalysisUtil.getMessagesFromResponse(
                                heartbeatResponse, HeartbeatMessage.class);
                if (!heartbeats.isEmpty()) {
                    gotHeartbeatResponse = true;
                }
            }
            if (graphDetails.hasStateInfo(state)) {
                Set<ContextProperty> reachedProperties =
                        graphDetails.getStateInfo(state).getContextPropertiesWhenReached();
                if (reachedProperties.contains(ContextProperty.IN_RESUMPTION_FLOW)) {
                    resumptionFound = true;
                }
                if (reachedProperties.contains(ContextProperty.ACCEPTED_RENEGOTIATION)
                        || canRenegotiateFromState(state, stateMachine, graphDetails)) {
                    renegotiationFound = true;
                }
                if (reachedProperties.contains(ContextProperty.IS_TLS13_FLOW)
                        && reachedProperties.contains(
                                ContextProperty.HANDSHAKE_FINISHED_CORRECTLY)) {
                    tls13CompletedFound = true;
                }
                if (reachedProperties.contains(ContextProperty.IS_TLS12_FLOW)
                        && reachedProperties.contains(
                                ContextProperty.HANDSHAKE_FINISHED_CORRECTLY)) {
                    tls12CompletedFound = true;
                }
                if (reachedProperties.contains(ContextProperty.CLIENT_AUTH_REQUESTED)) {
                    certRequested = true;
                }
                if (reachedProperties.contains(ContextProperty.HANDSHAKE_FINISHED_CORRECTLY)
                        && reachedProperties.contains(ContextProperty.IS_TLS12_FLOW)) {
                    for (TlsWord word : stateMachine.getAlphabet()) {
                        if (TlsWordType.effectivelyEquals(
                                TlsWordType.ANY_CLIENT_HELLO, word.getType())) {
                            SulResponse response =
                                    (SulResponse)
                                            stateMachine.getMealyMachine().getOutput(state, word);
                            List<ServerHelloMessage> hsMessages =
                                    AnalysisUtil.getMessagesFromResponse(
                                            response, ServerHelloMessage.class);
                            if (!hsMessages.isEmpty()) {
                                renegotiationFound = true;
                            }
                        }
                    }
                }
            }
        }

        noCompletedFound = !tls13CompletedFound && !tls12CompletedFound;
        certRequestedAndNoCompleted = certRequested && noCompletedFound;
        certRequestedAndCompleted = certRequested && !noCompletedFound;

        if (resumptionFound) {
            statInfoList.add("RESUMPTION");
        }
        if (renegotiationFound) {
            statInfoList.add("RENEGOTIATION");
        }
        if (tls13CompletedFound) {
            statInfoList.add("TLS13_COMPLETED");
        }
        if (tls12CompletedFound) {
            statInfoList.add("TLS12_COMPLETED");
        }
        if (noCompletedFound) {
            statInfoList.add("NO_COMPLETED");
        }
        if (certRequested) {
            statInfoList.add("CERT_REQUESTED");
        }
        if (certRequestedAndNoCompleted) {
            statInfoList.add("CERT_REQUESTED_AND_NO_COMPLETED");
        }
        if (certRequestedAndCompleted) {
            statInfoList.add("CERT_REQUESTED_AND_COMPLETED");
        }
        if (gotHeartbeatResponse) {
            statInfoList.add("HEARTBEAT_RESPONSE");
        }

        statInfoList.add("States[" + stateMachine.getMealyMachine().getStates().size() + "]");
        return statInfoList;
    }

    public static boolean canRenegotiateFromState(
            Object state, StateMachine stateMachine, GraphDetails graphDetails) {
        boolean didRenegotiate = false;
        if (graphDetails.getFinStates().contains(state)) {
            for (TlsWord input :
                    stateMachine.getAlphabet().stream()
                            .filter(
                                    word ->
                                            TlsWordType.effectivelyEquals(
                                                    TlsWordType.ANY_CLIENT_HELLO, word.getType()))
                            .collect(Collectors.toList())) {
                SulResponse response =
                        (SulResponse) stateMachine.getMealyMachine().getOutput(state, input);
                List<ServerHelloMessage> hsMessages =
                        AnalysisUtil.getMessagesFromResponse(response, ServerHelloMessage.class);
                if (!hsMessages.isEmpty()) {
                    didRenegotiate = true;
                    break;
                }
            }
        }
        return didRenegotiate;
    }
}
