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
import de.rub.nds.statevulnfinder.core.algorithm.words.ClientKeyExchangeWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.FinishedWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextProperty;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.constants.StateMachineIssueType;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.core.issue.BBAndPOVulnerability;
import de.rub.nds.statevulnfinder.core.issue.IgnoredInputIssue;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import de.rub.nds.statevulnfinder.core.issue.UnwantedHappyFlowVulnerability;
import de.rub.nds.statevulnfinder.server.analysis.transition.ServerTransitionAnalyzer;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class CommonIssueFilter {

    public static CommonIssueCheckResult filterIssues(
            List<StateMachineIssue> initialIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails) {
        List<StateMachineIssue> coveredIssues = new LinkedList<>();
        Set<CommonIssue> commonIssuesFound = new HashSet<>();

        coveredIssues.addAll(
                checkIgnoresCcsAfterFinIssue(
                        initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                internalErrorUponDummyCcs(
                        initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                rejectsHttps(initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                illegalParameterUponChAfterHrrEnforcingCh(
                        initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                postHandshakeCcsToDummyCcsState(
                        initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                finStateNameConfusionBug(
                        initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                multipleChsAllowed(initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                startingWithDummyCcsLeadsToTerminal(
                        initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                duplicateDummyStateNotConsideredErrorStateBug(
                        initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                closeNotifyIgnored(initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                httpsIgnoredDuringHandshakeButNotAsFirst(
                        initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                tls13keyUpdateToErrorState(
                        initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                ignoresCcsAfterHandshakeTls13(
                        initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                rejected3DesChWithHandshakeFailure(
                        initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                multipleChsRejectedWithHandshakeFailure(
                        initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                multipleChsRejectedWithIllegalParameter(
                        initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                multipleChsRejectedWithCloseNotify(
                        initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                rejectsChWithoutRecordSocketException(
                        initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                rejectedOurCert(initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                acceptsRenegotiationButClosesConnectionWithShFlight(
                        initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                acceptsUnsolicitatedCert(
                        initialIssues, stateMachine, graphDetails, commonIssuesFound));
        coveredIssues.addAll(
                assumedCacheFilterOracleBug(
                        initialIssues, stateMachine, graphDetails, commonIssuesFound));
        List<StateMachineIssue> remainingIssues = new LinkedList<>(initialIssues);
        remainingIssues.removeAll(coveredIssues);
        return new CommonIssueCheckResult(remainingIssues, commonIssuesFound);
    }

    private static List<StateMachineIssue> getIssuesByType(
            StateMachineIssueType type, List<StateMachineIssue> allIssues) {
        return allIssues.stream()
                .filter(
                        issue -> {
                            return issue.getType() == type;
                        })
                .collect(Collectors.toList());
    }

    private static List<StateMachineIssue> checkIgnoresCcsAfterFinIssue(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> relevantIssues =
                getIssuesByType(StateMachineIssueType.NO_FAIL_FAST, givenIssues);
        List<StateMachineIssue> dummyCcsLoops = new LinkedList<>();
        List<StateMachineIssue> ccsToTerminals = new LinkedList<>();
        for (StateMachineIssue issue : relevantIssues) {
            Object secondToLastState =
                    AnalysisUtil.getStateReachedWithMessageSequence(
                            stateMachine, issue.getPath(), 1);
            Object lastState =
                    AnalysisUtil.getStateReachedWithMessageSequence(stateMachine, issue.getPath());
            if (secondToLastState != null) {
                boolean secondToLastIsFin = graphDetails.getFinStates().contains(secondToLastState);
                boolean lastIsFin = graphDetails.getFinStates().contains(lastState);
                boolean lastIsTerminal =
                        AnalysisUtil.isTerminalState(
                                stateMachine, lastState, graphDetails.getErrorStates());
                if (AnalysisUtil.lastInputInSequenceOfType(TlsWordType.CCS, issue.getPath())
                        && secondToLastIsFin
                        && lastIsTerminal) {
                    ccsToTerminals.add(issue);
                } else if (AnalysisUtil.lastInputInSequenceOfType(
                                TlsWordType.DUMMY_CCS, issue.getPath())
                        && lastIsFin
                        && secondToLastState == lastState) {
                    dummyCcsLoops.add(issue);
                }
            }
        }

        if (!dummyCcsLoops.isEmpty() && !ccsToTerminals.isEmpty()) {
            commonIssuesFound.add(CommonIssue.IGNORES_CCS_AFTER_FIN);
            dummyCcsLoops.addAll(ccsToTerminals);
            return dummyCcsLoops;
        }
        return new LinkedList<>();
    }

    private static List<StateMachineIssue> internalErrorUponDummyCcs(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> relevantIssues =
                getIssuesByType(StateMachineIssueType.INTERNAL_ERROR, givenIssues);
        List<StateMachineIssue> filteredIssues = new LinkedList<>();
        for (StateMachineIssue issue : relevantIssues) {
            if (issue.getPath().size() > 3 && isHandshakeToCcsFlow(issue)) {
                filteredIssues.add(issue);
            }
        }
        if (!filteredIssues.isEmpty()) {
            // ensure this is the only internal error, otherwise it may not be the same issue
            if (filteredIssues.containsAll(relevantIssues)) {
                commonIssuesFound.add(CommonIssue.INTERNAL_ERROR_AFTER_DUMMY_CCS);
            } else {
                filteredIssues.clear();
            }
        }
        return filteredIssues;
    }

    private static boolean isHandshakeToCcsFlow(StateMachineIssue issue) {
        boolean flowWithoutClientAuth =
                AnalysisUtil.trailingInputInSequenceOfType(
                                TlsWordType.DUMMY_CCS, issue.getPath(), 1)
                        && AnalysisUtil.trailingInputInSequenceOfType(
                                TlsWordType.CLIENT_KEY_EXCHANGE, issue.getPath(), 2)
                        && AnalysisUtil.trailingInputInSequenceOfType(
                                TlsWordType.ANY_CLIENT_HELLO, issue.getPath(), 3);
        boolean flowWithClientAuth =
                issue.getPath().size() >= 5
                        && AnalysisUtil.trailingInputInSequenceOfType(
                                TlsWordType.DUMMY_CCS, issue.getPath(), 1)
                        && AnalysisUtil.trailingInputInSequenceOfType(
                                TlsWordType.CERTIFICATE_VERIFY, issue.getPath(), 2)
                        && AnalysisUtil.trailingInputInSequenceOfType(
                                TlsWordType.EMPTY_CERTIFICATE, issue.getPath(), 4);
        return flowWithClientAuth || flowWithoutClientAuth;
    }

    private static List<StateMachineIssue> rejectsHttps(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> relevantIssues =
                getIssuesByType(StateMachineIssueType.NO_HAPPY_FLOW, givenIssues);
        List<StateMachineIssue> filteredIssues = new LinkedList<>();
        for (StateMachineIssue issue : relevantIssues) {
            if (AnalysisUtil.lastInputInSequenceOfType(
                    TlsWordType.HTTPS_REQUEST, issue.getPath())) {
                Object previousState =
                        AnalysisUtil.getStateReachedWithMessageSequence(
                                stateMachine, issue.getPath(), 1);
                if (previousState != null
                        && graphDetails.getBenignStateInfoMap().get(previousState) != null) {
                    if (graphDetails
                            .getBenignStateInfoMap()
                            .get(previousState)
                            .getContextPropertiesWhenReached()
                            .contains(ContextProperty.HANDSHAKE_FINISHED_CORRECTLY)) {
                        filteredIssues.add(issue);
                    }
                }
            }
        }
        if (!filteredIssues.isEmpty()) {
            commonIssuesFound.add(CommonIssue.REJECTS_HTTPS);
        }
        return filteredIssues;
    }

    // ILLEGAL_PARAMETER_UPON_CH_AFTER_HRR_ENFORCING_CH
    private static List<StateMachineIssue> illegalParameterUponChAfterHrrEnforcingCh(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> relevantIssues =
                getIssuesByType(StateMachineIssueType.NO_HAPPY_FLOW, givenIssues);
        List<StateMachineIssue> filteredIssues = new LinkedList<>();
        for (StateMachineIssue issue : relevantIssues) {
            if (issue.getPath().size() == 2
                    && AnalysisUtil.lastInputInSequenceOfType(
                            TlsWordType.TLS13_CLIENT_HELLO, issue.getPath())
                    && AnalysisUtil.trailingInputInSequenceOfType(
                            TlsWordType.HRR_ENFORCING_HELLO, issue.getPath(), 1)
                    && AnalysisUtil.getLastResponse(issue.getPath(), stateMachine)
                                    .getResponseFingerprint()
                            != null
                    && AnalysisUtil.getLastResponse(issue.getPath(), stateMachine)
                                    .getResponseFingerprint()
                                    .getMessageList()
                                    .size()
                            == 1
                    && AnalysisUtil.getLastResponse(issue.getPath(), stateMachine)
                                    .getResponseFingerprint()
                                    .getMessageList()
                                    .get(0)
                            instanceof AlertMessage
                    && ((AlertMessage)
                                            AnalysisUtil.getLastResponse(
                                                            issue.getPath(), stateMachine)
                                                    .getResponseFingerprint()
                                                    .getMessageList()
                                                    .get(0))
                                    .getDescription()
                                    .getValue()
                            == AlertDescription.ILLEGAL_PARAMETER.getValue()) {
                filteredIssues.add(issue);
            }
        }
        if (!filteredIssues.isEmpty()) {
            commonIssuesFound.add(CommonIssue.ILLEGAL_PARAMETER_UPON_CH_AFTER_HRR_ENFORCING_CH);
        }
        return filteredIssues;
    }

    // POST_HANDSHAKE_CCS_TO_DUMMY_CCS
    private static List<StateMachineIssue> postHandshakeCcsToDummyCcsState(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> relevantIssues =
                getIssuesByType(StateMachineIssueType.UNWANTED_HAPPY_FLOW, givenIssues);
        relevantIssues.addAll(getIssuesByType(StateMachineIssueType.NO_FAIL_FAST, givenIssues));
        List<StateMachineIssue> filteredIssues = new LinkedList<>();
        // make the result less noisy by tracking ignored dummy CCS
        List<StateMachineIssue> dummyCcsIgnored = new LinkedList<>();
        for (StateMachineIssue issue : relevantIssues) {
            if (issue.getPath().size() >= 5
                    && AnalysisUtil.lastInputInSequenceOfType(TlsWordType.ANY_CCS, issue.getPath())
                    && AnalysisUtil.trailingInputInSequenceOfType(
                            TlsWordType.FINISHED, issue.getPath(), 1)) {
                Object lastState =
                        AnalysisUtil.getStateReachedWithMessageSequence(
                                stateMachine, issue.getPath());
                Object secondToLastState =
                        AnalysisUtil.getStateReachedWithMessageSequence(
                                stateMachine, issue.getPath(), 1);

                if (graphDetails.getBenignStateInfoMap().containsKey(lastState)
                        && graphDetails
                                .getBenignStateInfoMap()
                                .get(lastState)
                                .getNames()
                                .contains(TlsWordType.DUMMY_CCS.name())
                        && issue instanceof UnwantedHappyFlowVulnerability) {
                    filteredIssues.add(issue);
                } else if (lastState == secondToLastState
                        && AnalysisUtil.lastInputInSequenceOfType(
                                TlsWordType.DUMMY_CCS, issue.getPath())
                        && issue instanceof IgnoredInputIssue) {
                    dummyCcsIgnored.add(issue);
                }
            }
        }

        if (!filteredIssues.isEmpty()) {
            commonIssuesFound.add(CommonIssue.POST_HANDSHAKE_CCS_TO_DUMMY_CCS_STATE);
            filteredIssues.addAll(dummyCcsIgnored);
            if (!dummyCcsIgnored.isEmpty()) {
                commonIssuesFound.add(
                        CommonIssue.POST_HANDSHAKE_CCS_TO_DUMMY_CCS_STATE_BUT_IGNORES_DUMMY_CCS);
            }
        }
        return filteredIssues;
    }

    // FIN_STATE_NAME_CONFUSION_BUG
    private static List<StateMachineIssue> finStateNameConfusionBug(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> relevantIssues =
                getIssuesByType(StateMachineIssueType.STATE_CONFUSION, givenIssues);
        List<StateMachineIssue> filteredIssues = new LinkedList<>();
        for (StateMachineIssue issue : relevantIssues) {
            boolean filterApplies = true;
            List<List<TlsWordType>> expectedBugInputTypeSequences = new LinkedList<>();
            expectedBugInputTypeSequences.add(
                    List.of(
                            TlsWordType.ANY_CLIENT_HELLO,
                            TlsWordType.CLIENT_KEY_EXCHANGE,
                            TlsWordType.CCS,
                            TlsWordType.FINISHED));
            expectedBugInputTypeSequences.add(
                    List.of(
                            TlsWordType.ANY_CLIENT_HELLO,
                            TlsWordType.EMPTY_CERTIFICATE,
                            TlsWordType.CLIENT_KEY_EXCHANGE,
                            TlsWordType.CERTIFICATE_VERIFY,
                            TlsWordType.CCS,
                            TlsWordType.FINISHED));
            if (issue.toString()
                            .contains(
                                    "is already known as [HTTPS_REQUEST, TLS12_CLIENT_HELLO] applying unexpected name FINISHED")
                    || issue.toString()
                            .contains(
                                    "is already known as [TLS12_CLIENT_HELLO] applying unexpected name FINISHED")) {
                int comparisonIndex = 0;
                for (TlsWord input : issue.getPath()) {
                    boolean sequenceIndexMatches = false;
                    for (List<TlsWordType> sequence : expectedBugInputTypeSequences) {
                        if (comparisonIndex < sequence.size()
                                && TlsWordType.effectivelyEquals(
                                        sequence.get(comparisonIndex), input.getType())) {
                            sequenceIndexMatches = true;
                            break;
                        }
                    }
                    if (!sequenceIndexMatches) {
                        filterApplies = false;
                        break;
                    }
                    comparisonIndex++;
                }
                if (filterApplies) {
                    filteredIssues.add(issue);
                }
            }
        }
        if (!filteredIssues.isEmpty()) {
            commonIssuesFound.add(CommonIssue.FIN_STATE_NAME_CONFUSION_BUG);
        }
        return filteredIssues;
    }

    // MULTPILE_CHS_ALLOWED_HANDSHAKE
    // MULTPILE_CHS_ALLOWED_RENEGOTIATION
    private static List<StateMachineIssue> multipleChsAllowed(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> relevantIssues =
                getIssuesByType(StateMachineIssueType.NO_FAIL_FAST, givenIssues);
        List<StateMachineIssue> multipleChsInHandshake = new LinkedList<>();
        List<StateMachineIssue> multipleChsInRenegotiation = new LinkedList<>();

        boolean canCompleteHandshakeWithPartialTranscript = false;
        boolean canCompleteHandshakeButNoWithPartialTranscript = false;

        for (StateMachineIssue issue : relevantIssues) {
            if (issue.getPath().size() == 2
                    && TlsWordType.effectivelyEquals(
                            issue.getPath().get(0).getType(), TlsWordType.TLS12_CLIENT_HELLO)
                    && TlsWordType.effectivelyEquals(
                            issue.getPath().get(1).getType(), TlsWordType.TLS12_CLIENT_HELLO)
                    && AnalysisUtil.lastResponseContainsMessages(
                            issue.getPath(),
                            stateMachine,
                            false,
                            Set.of(
                                    ServerHelloMessage.class,
                                    CertificateMessage.class,
                                    ServerHelloDoneMessage.class))) {
                multipleChsInHandshake.add(issue);
            } else if (issue.getPath().size() > 2
                    && AnalysisUtil.lastInputInSequenceOfType(
                            TlsWordType.TLS12_CLIENT_HELLO, issue.getPath())
                    && AnalysisUtil.trailingInputInSequenceOfType(
                            TlsWordType.TLS12_CLIENT_HELLO, issue.getPath(), 1)
                    && graphDetails
                            .getFinStates()
                            .contains(
                                    AnalysisUtil.getStateReachedWithMessageSequence(
                                            stateMachine, issue.getPath(), 2))
                    && AnalysisUtil.lastResponseContainsMessages(
                            issue.getPath(),
                            stateMachine,
                            false,
                            Set.of(
                                    ServerHelloMessage.class,
                                    CertificateMessage.class,
                                    ServerHelloDoneMessage.class))) {
                multipleChsInRenegotiation.add(issue);
            }
        }
        if (!multipleChsInHandshake.isEmpty()) {
            commonIssuesFound.add(CommonIssue.MULTIPLE_CHS_ALLOWED_HANDSHAKE);
        }
        if (!multipleChsInRenegotiation.isEmpty()) {
            commonIssuesFound.add(CommonIssue.MULTIPLE_CHS_ALLOWED_RENEGOTIATION);
        }

        List<StateMachineIssue> returnToHappyFlowIssues = new LinkedList<>();
        // check for unwanted happy flows, i.e all issue paths that would be benign if it wasn't for
        // the multiple CHs
        relevantIssues = getIssuesByType(StateMachineIssueType.UNWANTED_HAPPY_FLOW, givenIssues);

        for (StateMachineIssue issue : relevantIssues) {
            boolean pathIsSuitable =
                    issue.getPath().size() > 2
                            && TlsWordType.effectivelyEquals(
                                    TlsWordType.TLS12_CLIENT_HELLO,
                                    issue.getPath().get(0).getType())
                            && TlsWordType.effectivelyEquals(
                                    TlsWordType.TLS12_CLIENT_HELLO,
                                    issue.getPath().get(1).getType());

            if (pathIsSuitable) {
                List<TlsWord> pathWithoutFirstCh = new LinkedList<>(issue.getPath());
                pathWithoutFirstCh.remove(0);
                ServerTransitionAnalyzer transitionAnalyzer =
                        new ServerTransitionAnalyzer(pathWithoutFirstCh, stateMachine);
                List<TlsWord> pathToFinished = new LinkedList<>();
                pathToFinished.add(pathWithoutFirstCh.get(0));
                pathToFinished.add(new ClientKeyExchangeWord());
                pathToFinished.add(new ChangeCipherSpecWord());
                pathToFinished.add(new FinishedWord());
                SulResponse responseForFullPath =
                        AnalysisUtil.getLastResponse(pathToFinished, stateMachine);
                boolean gotCcsFinForOnceCh =
                        !AnalysisUtil.getMessagesFromResponse(
                                        responseForFullPath, FinishedMessage.class)
                                .isEmpty();
                pathToFinished.add(0, issue.getPath().get(0));
                responseForFullPath = AnalysisUtil.getLastResponse(pathToFinished, stateMachine);
                boolean gotCcsFinForTwoChs =
                        !AnalysisUtil.getMessagesFromResponse(
                                        responseForFullPath, FinishedMessage.class)
                                .isEmpty();
                boolean isCorrectIfNotForMultipleChs = transitionAnalyzer.isEffectivelyBenignFlow();
                if (isCorrectIfNotForMultipleChs) {
                    returnToHappyFlowIssues.add(issue);
                }
                if (gotCcsFinForOnceCh && gotCcsFinForTwoChs) {
                    canCompleteHandshakeWithPartialTranscript = true;
                } else if (gotCcsFinForOnceCh && !gotCcsFinForTwoChs) {
                    canCompleteHandshakeButNoWithPartialTranscript = true;
                }
            }
        }
        if (canCompleteHandshakeWithPartialTranscript) {
            commonIssuesFound.add(
                    CommonIssue
                            .MULTIPLE_CHS_ALLOWED_AND_CAN_COMPLETE_HANDSHAKE_WITH_PARTIAL_TRANSCRIPT);
        }

        if (canCompleteHandshakeButNoWithPartialTranscript) {
            commonIssuesFound.add(
                    CommonIssue.MULTIPLE_CHS_ALLOWED_BUT_UNABLE_TO_COMPLETE_WITH_PARIAL_TRANSCRIPT);
        }

        multipleChsInHandshake.addAll(returnToHappyFlowIssues);
        multipleChsInHandshake.addAll(multipleChsInRenegotiation);
        return multipleChsInHandshake;
    }

    // STARTING_WITH_DUMMY_CCS_LEADS_TO_TERMINAL
    // STARTING_WITH_VARIOUS_GENERIC_INPUTS_LEADS_TO_TERMINAL
    private static List<StateMachineIssue> startingWithDummyCcsLeadsToTerminal(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> relevantIssues =
                getIssuesByType(StateMachineIssueType.NO_HAPPY_FLOW, givenIssues);
        List<StateMachineIssue> filteredIssues = new LinkedList<>();
        List<Object> terminalStates = new LinkedList<>();
        for (StateMachineIssue issue : relevantIssues) {
            boolean pathIsSuitable =
                    issue.getPath().size() == 2
                            && TlsWordType.effectivelyEquals(
                                    issue.getPath().get(0).getType(), TlsWordType.DUMMY_CCS);
            SulResponse lastResponse = AnalysisUtil.getLastResponse(issue.getPath(), stateMachine);
            boolean lastResponseIsEmpty =
                    !lastResponse.isIllegalTransitionFlag()
                            && lastResponse.getResponseFingerprint() != null
                            && lastResponse.getResponseFingerprint().getRecordList() != null
                            && lastResponse.getResponseFingerprint().getRecordList().isEmpty();
            Object firstState =
                    AnalysisUtil.getStateReachedWithMessageSequence(
                            stateMachine, List.of(issue.getPath().get(0)));
            boolean firstStateIsTerminal =
                    AnalysisUtil.isTerminalState(
                            stateMachine, firstState, graphDetails.getErrorStates());
            if (pathIsSuitable && lastResponseIsEmpty && firstStateIsTerminal) {
                filteredIssues.add(issue);
                terminalStates.add(firstState);
            }
        }

        List<StateMachineIssue> filteredIssuesNoFailFast = new LinkedList<>();
        relevantIssues = getIssuesByType(StateMachineIssueType.NO_FAIL_FAST, givenIssues);
        for (StateMachineIssue issue : relevantIssues) {
            List<TlsWord> pathSinceReset = AnalysisUtil.getPathSinceReset(issue.getPath());
            if (pathSinceReset.size() == 1
                    && AnalysisUtil.isTerminalState(
                            stateMachine,
                            AnalysisUtil.getStateReachedWithMessageSequence(
                                    stateMachine, pathSinceReset),
                            graphDetails.getErrorStates())) {
                filteredIssuesNoFailFast.add(issue);
            }
        }
        if (filteredIssuesNoFailFast.size() > 0) {
            commonIssuesFound.add(
                    CommonIssue.STARTING_WITH_VARIOUS_GENERIC_INPUTS_LEADS_TO_TERMINAL);
        }
        if (filteredIssues.size() > 0 && filteredIssuesNoFailFast.size() == 0) {
            commonIssuesFound.add(
                    CommonIssue.STARTING_WITH_DUMMY_CCS_LEADS_TO_TERMINAL_EXCLUSIVELY);
        }
        filteredIssues.addAll(filteredIssuesNoFailFast);
        return filteredIssues;
    }

    // DUPLICATE_DUMMY_STATE_NOT_CONSIDERED_ERROR_STATE_BUG
    private static List<StateMachineIssue> duplicateDummyStateNotConsideredErrorStateBug(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> relevantIssues =
                getIssuesByType(StateMachineIssueType.NO_FAIL_FAST, givenIssues);
        List<StateMachineIssue> filteredIssues = new LinkedList<>();
        for (StateMachineIssue issue : relevantIssues) {
            Object lastState =
                    AnalysisUtil.getStateReachedWithMessageSequence(stateMachine, issue.getPath());
            if (issue.toString()
                            .contains(
                                    "Illegal deviation from happy flow did not lead to error state")
                    && AnalysisUtil.getDummyStates(stateMachine).contains(lastState)) {
                filteredIssues.add(issue);
            }
        }
        if (!filteredIssues.isEmpty()) {
            commonIssuesFound.add(CommonIssue.DUPLICATE_DUMMY_STATE_NOT_CONSIDERED_ERROR_STATE_BUG);
        }
        return filteredIssues;
    }

    // HTTPS_IGNORED_DURING_HANDSHAKE_BUT_NOT_AS_FIRST
    private static List<StateMachineIssue> httpsIgnoredDuringHandshakeButNotAsFirst(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> relevantIssues =
                getIssuesByType(StateMachineIssueType.NO_FAIL_FAST, givenIssues);
        List<StateMachineIssue> filteredIssues = new LinkedList<>();
        for (StateMachineIssue issue : relevantIssues) {
            if (issue.getPath().size() > 1
                    && AnalysisUtil.lastInputInSequenceOfType(
                            TlsWordType.HTTPS_REQUEST, issue.getPath())) {
                Object secondToLastState =
                        AnalysisUtil.getStateReachedWithMessageSequence(
                                stateMachine, issue.getPath(), 1);
                SulResponse lastResponse =
                        AnalysisUtil.getLastResponse(issue.getPath(), stateMachine);
                if (graphDetails.hasStateInfo(secondToLastState)
                        && graphDetails
                                .getStateInfo(secondToLastState)
                                .getContextPropertiesWhenReached()
                                .contains(ContextProperty.HANDSHAKE_UNFINISHED)
                        && lastResponse.getResponseFingerprint() != null
                        && lastResponse.getResponseFingerprint().getRecordList().isEmpty()) {
                    filteredIssues.add(issue);
                }
            }
        }
        if (!filteredIssues.isEmpty()) {
            commonIssuesFound.add(CommonIssue.HTTPS_IGNORED_DURING_HANDSHAKE_BUT_NOT_AS_FIRST);
        }
        return filteredIssues;
    }
    // CLOSE_NOTIFY_IGNORED
    private static List<StateMachineIssue> closeNotifyIgnored(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> relevantIssues =
                getIssuesByType(StateMachineIssueType.NO_FAIL_FAST, givenIssues);
        List<StateMachineIssue> filteredIssues = new LinkedList<>();
        for (StateMachineIssue issue : relevantIssues) {
            if (AnalysisUtil.lastInputInSequenceOfType(TlsWordType.CLOSE_NOTIFY, issue.getPath())) {
                filteredIssues.add(issue);
            }
        }
        if (!filteredIssues.isEmpty()) {
            commonIssuesFound.add(CommonIssue.CLOSE_NOTIFY_IGNORED);
        }
        return filteredIssues;
    }

    // TLS_13_KEY_UPDATE_TO_ERROR_STATE
    private static List<StateMachineIssue> tls13keyUpdateToErrorState(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> relevantIssues =
                getIssuesByType(StateMachineIssueType.NO_HAPPY_FLOW, givenIssues);
        List<StateMachineIssue> filteredIssues = new LinkedList<>();
        for (StateMachineIssue issue : relevantIssues) {
            if (issue.getPath().size() > 1) {
                Object secondToLastState =
                        AnalysisUtil.getStateReachedWithMessageSequence(
                                stateMachine, issue.getPath(), 1);
                if (graphDetails.hasStateInfo(secondToLastState)
                        && graphDetails.getFinStates().contains(secondToLastState)
                        && AnalysisUtil.lastInputInSequenceOfType(
                                TlsWordType.KEY_UPDATE, issue.getPath())) {
                    filteredIssues.add(issue);
                }
            }
        }
        if (!filteredIssues.isEmpty()) {
            commonIssuesFound.add(CommonIssue.TLS_13_KEY_UPDATE_TO_ERROR_STATE);
        }
        return filteredIssues;
    }

    // IGNORES_CCS_AFTER_HANDSHAKE_TLS13
    private static List<StateMachineIssue> ignoresCcsAfterHandshakeTls13(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> relevantIssues =
                getIssuesByType(StateMachineIssueType.NO_FAIL_FAST, givenIssues);
        List<StateMachineIssue> filteredIssues = new LinkedList<>();
        List<StateMachineIssue> dummyCcsIgnored = new LinkedList<>();
        List<StateMachineIssue> realCcsIgnored = new LinkedList<>();
        for (StateMachineIssue issue : relevantIssues) {
            boolean lastIsCcs =
                    AnalysisUtil.lastInputInSequenceOfType(TlsWordType.ANY_CCS, issue.getPath());
            Object finalState =
                    AnalysisUtil.getStateReachedWithMessageSequence(stateMachine, issue.getPath());
            boolean lastDoesNotChangeState =
                    finalState
                            == AnalysisUtil.getStateReachedWithMessageSequence(
                                    stateMachine, issue.getPath(), 1);
            boolean lastStateIsTls13HandshakeCompleted =
                    graphDetails.hasStateInfo(finalState)
                            && graphDetails
                                    .getStateInfo(finalState)
                                    .getContextPropertiesWhenReached()
                                    .containsAll(
                                            List.of(
                                                    ContextProperty.HANDSHAKE_FINISHED_CORRECTLY,
                                                    ContextProperty.IS_TLS13_FLOW));
            if (lastIsCcs && lastDoesNotChangeState && lastStateIsTls13HandshakeCompleted) {
                if (AnalysisUtil.lastInputInSequenceOfType(TlsWordType.CCS, issue.getPath())) {
                    realCcsIgnored.add(issue);
                } else {
                    dummyCcsIgnored.add(issue);
                }
            }
        }
        // if this did not appear for both types of CCS, it is not the same issue
        if (realCcsIgnored.size() == dummyCcsIgnored.size()) {
            filteredIssues.addAll(realCcsIgnored);
            filteredIssues.addAll(dummyCcsIgnored);
        }
        if (!filteredIssues.isEmpty()) {
            commonIssuesFound.add(CommonIssue.IGNORES_CCS_AFTER_HANDSHAKE_TLS13);
        }
        return filteredIssues;
    }

    // REJECTED_3DES_CH_WITH_HANDSHAKE_FAILURE
    private static List<StateMachineIssue> rejected3DesChWithHandshakeFailure(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> relevantIssues =
                getIssuesByType(StateMachineIssueType.NO_HAPPY_FLOW, givenIssues);
        List<StateMachineIssue> filteredIssues = new LinkedList<>();
        for (StateMachineIssue issue : relevantIssues) {
            if (issue.getPath().size() == 1
                    && issue.getPath().get(0).getType() == TlsWordType.TLS12_CLIENT_HELLO
                    && ((ClientHelloWord) issue.getPath().get(0))
                            .getSuite()
                            .name()
                            .contains("3DES")) {
                List<AlertMessage> alerts =
                        AnalysisUtil.getMessagesFromResponse(
                                AnalysisUtil.getLastResponse(issue.getPath(), stateMachine),
                                AlertMessage.class);
                if (alerts.size() == 1) {
                    AlertMessage alert = alerts.get(0);
                    if (alert.getDescription().getValue()
                            == AlertDescription.HANDSHAKE_FAILURE.getValue()) {
                        filteredIssues.add(issue);
                    }
                }
            }
        }
        if (!filteredIssues.isEmpty()) {
            commonIssuesFound.add(CommonIssue.REJECTED_3DES_CH_WITH_HANDSHAKE_FAILURE);
        }
        return filteredIssues;
    }

    // MULTIPLE_CHS_REJECTED_WITH_HANDSHAKE_FAILURE
    private static List<StateMachineIssue> multipleChsRejectedWithHandshakeFailure(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> filteredIssues =
                rejectsChWithAlert(givenIssues, stateMachine, AlertDescription.HANDSHAKE_FAILURE);
        if (filteredIssues.size() > 1) {
            commonIssuesFound.add(CommonIssue.MULTIPLE_CHS_REJECTED_WITH_HANDSHAKE_FAILURE);
        }
        return filteredIssues;
    }

    // MULTIPLE_CHS_REJECTED_WITH_ILLEGAL_PARAMETER
    private static List<StateMachineIssue> multipleChsRejectedWithIllegalParameter(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> filteredIssues =
                rejectsChWithAlert(givenIssues, stateMachine, AlertDescription.ILLEGAL_PARAMETER);
        if (filteredIssues.size() > 1) {
            commonIssuesFound.add(CommonIssue.MULTIPLE_CHS_REJECTED_WITH_ILLEGAL_PARAMETER);
        }
        return filteredIssues;
    }

    // MULTIPLE_CHS_REJECTED_WITH_CLOSE_NOTIFY
    private static List<StateMachineIssue> multipleChsRejectedWithCloseNotify(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> filteredIssues =
                rejectsChWithAlert(givenIssues, stateMachine, AlertDescription.CLOSE_NOTIFY);
        if (filteredIssues.size() > 1) {
            commonIssuesFound.add(CommonIssue.MULTIPLE_CHS_REJECTED_WITH_CLOSE_NOTIFY);
        }
        return filteredIssues;
    }

    private static List<StateMachineIssue> rejectsChWithAlert(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            AlertDescription alertDescription) {
        List<StateMachineIssue> filteredIssues = new LinkedList<>();
        List<StateMachineIssue> relevantIssues =
                getIssuesByType(StateMachineIssueType.NO_HAPPY_FLOW, givenIssues);
        for (StateMachineIssue issue : relevantIssues) {
            if (issue.getPath().size() == 1
                    && TlsWordType.effectivelyEquals(
                            TlsWordType.ANY_CLIENT_HELLO, issue.getPath().get(0).getType())) {
                List<AlertMessage> alerts =
                        AnalysisUtil.getMessagesFromResponse(
                                AnalysisUtil.getLastResponse(issue.getPath(), stateMachine),
                                AlertMessage.class);
                if (alerts.size() == 1) {
                    AlertMessage alert = alerts.get(0);
                    if (alert.getDescription().getValue() == alertDescription.getValue()) {
                        filteredIssues.add(issue);
                    }
                }
            }
        }
        return filteredIssues;
    }

    // MULTIPLE_CHS_REJECTED_NO_RECORD_SOCKET_EXCEPTION
    private static List<StateMachineIssue> rejectsChWithoutRecordSocketException(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> filteredIssues = new LinkedList<>();
        List<StateMachineIssue> relevantIssues =
                getIssuesByType(StateMachineIssueType.NO_HAPPY_FLOW, givenIssues);
        for (StateMachineIssue issue : relevantIssues) {
            if (issue.getPath().size() == 1
                    && TlsWordType.effectivelyEquals(
                            TlsWordType.ANY_CLIENT_HELLO, issue.getPath().get(0).getType())) {
                SulResponse response = AnalysisUtil.getLastResponse(issue.getPath(), stateMachine);
                boolean isEmptyRecordList =
                        !response.isIllegalTransitionFlag()
                                && response.getResponseFingerprint() != null
                                && response.getResponseFingerprint().getRecordList() != null
                                && response.getResponseFingerprint().getRecordList().isEmpty();
                boolean isSocketException =
                        isEmptyRecordList
                                && response.getResponseFingerprint().getSocketState()
                                        == SocketState.SOCKET_EXCEPTION;
                if (isEmptyRecordList && isSocketException) {
                    filteredIssues.add(issue);
                }
            }
        }
        if (!filteredIssues.isEmpty()) {
            commonIssuesFound.add(CommonIssue.MULTIPLE_CHS_REJECTED_NO_RECORD_SOCKET_EXCEPTION);
        }
        return filteredIssues;
    }

    // REJECTED_OUR_CERT
    private static List<StateMachineIssue> rejectedOurCert(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> filteredIssues = new LinkedList<>();
        List<StateMachineIssue> relevantIssues =
                getIssuesByType(StateMachineIssueType.NO_HAPPY_FLOW, givenIssues);
        for (StateMachineIssue issue : relevantIssues) {
            if ((issue.getPath().get(issue.getPath().size() - 1).getType()
                                    == TlsWordType.CERTIFICATE
                            || issue.getPath().get(issue.getPath().size() - 1).getType()
                                    == TlsWordType.EMPTY_CERTIFICATE)
                    && (issue.getPath().size() == 2 || issue.getPath().size() == 3)) {
                filteredIssues.add(issue);
            }
        }
        if (!filteredIssues.isEmpty()) {
            commonIssuesFound.add(CommonIssue.REJECTED_OUR_CERT);
        }
        return filteredIssues;
    }

    // ACCEPTS_RENEGOTIATION_BUT_CLOSES_CONNECTION_WITH_SH_FLIGHT
    private static List<StateMachineIssue> acceptsRenegotiationButClosesConnectionWithShFlight(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> filteredIssues = new LinkedList<>();
        List<StateMachineIssue> filteredResumptionIssues = new LinkedList<>();
        List<StateMachineIssue> relevantIssues =
                getIssuesByType(StateMachineIssueType.ODD_ERROR_STATE_TRANSITION, givenIssues);
        for (StateMachineIssue issue : relevantIssues) {
            boolean sufficientLength = issue.getPath().size() > 2;
            boolean lastIsCh =
                    TlsWordType.effectivelyEquals(
                            TlsWordType.ANY_CLIENT_HELLO,
                            issue.getPath().get(issue.getPath().size() - 1).getType());
            boolean lastIsResumingch =
                    TlsWordType.effectivelyEquals(
                            TlsWordType.RESUMING_HELLO,
                            issue.getPath().get(issue.getPath().size() - 1).getType());
            Object secondToLastState =
                    AnalysisUtil.getStateReachedWithMessageSequence(
                            stateMachine, issue.getPath(), 1);
            SulResponse lastResponse = AnalysisUtil.getLastResponse(issue.getPath(), stateMachine);
            boolean secondToLastStateIsFinished =
                    graphDetails.hasStateInfo(secondToLastState)
                            && graphDetails
                                    .getStateInfo(secondToLastState)
                                    .getContextPropertiesWhenReached()
                                    .contains(ContextProperty.HANDSHAKE_FINISHED_CORRECTLY);
            Set<Class<?>> handshakeMessages =
                    AnalysisUtil.getMessagesFromResponse(lastResponse, HandshakeMessage.class)
                            .stream()
                            .map(Object::getClass)
                            .collect(Collectors.toSet());
            boolean filterApplies =
                    sufficientLength
                            && lastIsCh
                            && secondToLastStateIsFinished
                            && handshakeMessages.contains(ServerHelloMessage.class)
                            && handshakeMessages.contains(CertificateMessage.class)
                            && handshakeMessages.contains(ServerHelloDoneMessage.class);
            boolean filterAppliesForResumptionReneg =
                    sufficientLength
                            && lastIsResumingch
                            && secondToLastStateIsFinished
                            && handshakeMessages.contains(ServerHelloMessage.class)
                            && handshakeMessages.contains(FinishedMessage.class);
            if (filterApplies) {
                filteredIssues.add(issue);
            } else if (filterAppliesForResumptionReneg) {
                filteredResumptionIssues.add(issue);
            }
        }
        if (!filteredIssues.isEmpty()) {
            commonIssuesFound.add(
                    CommonIssue.ACCEPTS_RENEGOTIATION_BUT_CLOSES_CONNECTION_WITH_SH_FLIGHT);
        }
        if (!filteredResumptionIssues.isEmpty()) {
            commonIssuesFound.add(
                    CommonIssue
                            .ACCEPTS_RENEGOTIATION_BUT_CLOSES_CONNECTION_WITH_SH_FLIGHT_RESUMPTION);
        }
        filteredIssues.addAll(filteredResumptionIssues);
        return filteredIssues;
    }

    // ACCEPTS_UNSOLICITATED_CERTIFICATE
    private static List<StateMachineIssue> acceptsUnsolicitatedCert(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> filteredIssues = new LinkedList<>();
        List<StateMachineIssue> relevantIssues =
                getIssuesByType(StateMachineIssueType.UNWANTED_HAPPY_FLOW, givenIssues);
        List<StateMachineIssue> noFailFastIssues =
                getIssuesByType(StateMachineIssueType.NO_FAIL_FAST, givenIssues);
        for (StateMachineIssue issue : relevantIssues) {

            boolean sufficientLength = issue.getPath().size() > 2;
            boolean secondIsCert =
                    sufficientLength
                            && issue.getPath().get(1).getType().name().endsWith("CERTIFICATE");
            Object lastState =
                    AnalysisUtil.getStateReachedWithMessageSequence(stateMachine, issue.getPath());
            boolean noCertRequestReceived =
                    graphDetails.hasStateInfo(lastState)
                            && !graphDetails
                                    .getStateInfo(lastState)
                                    .getContextPropertiesWhenReached()
                                    .contains(ContextProperty.CLIENT_AUTH_REQUESTED);
            boolean lastIsFinishedState =
                    graphDetails
                            .getStateInfo(lastState)
                            .getContextPropertiesWhenReached()
                            .contains(ContextProperty.HANDSHAKE_FINISHED_CORRECTLY);
            boolean lastIsBleichenbacherState =
                    graphDetails
                            .getStateInfo(lastState)
                            .getContextPropertiesWhenReached()
                            .contains(ContextProperty.BLEICHENBACHER_PATH);
            if (secondIsCert && noCertRequestReceived && lastIsFinishedState) {
                List<TlsWord> messagesWithoutCert = new LinkedList<>(issue.getPath());
                messagesWithoutCert.remove(1);
                ServerTransitionAnalyzer analyzer =
                        new ServerTransitionAnalyzer(messagesWithoutCert, stateMachine);
                if (analyzer.isEffectivelyBenignFlow()) {
                    filteredIssues.add(issue);
                }
            } else if (secondIsCert && noCertRequestReceived && lastIsBleichenbacherState) {
                filteredIssues.add(issue);
            }
        }
        if (!filteredIssues.isEmpty()) {
            commonIssuesFound.add(CommonIssue.ACCEPTS_UNSOLICITATED_CERTIFICATE);
            for (StateMachineIssue issue : noFailFastIssues) {
                if (issue.getPath().size() == 2
                        && issue.getPath().get(1).getType().name().endsWith("CERTIFICATE")
                        && TlsWordType.effectivelyEquals(
                                TlsWordType.ANY_CLIENT_HELLO, issue.getPath().get(0).getType())) {
                    filteredIssues.add(issue);
                }
            }
        }
        return filteredIssues;
    }

    // ASSUMED_CACHE_FILTER_ORACLE_BUG
    private static List<StateMachineIssue> assumedCacheFilterOracleBug(
            List<StateMachineIssue> givenIssues,
            StateMachine stateMachine,
            GraphDetails graphDetails,
            Set<CommonIssue> commonIssuesFound) {
        List<StateMachineIssue> filteredIssues = new LinkedList<>();
        List<StateMachineIssue> relevantIssues =
                getIssuesByType(StateMachineIssueType.BLEICHENBACHER, givenIssues);
        relevantIssues.addAll(getIssuesByType(StateMachineIssueType.PADDING_ORACLE, givenIssues));

        for (StateMachineIssue issue : relevantIssues) {
            Object successor1 = null;
            Object successor2 = null;
            List<TlsWord> path1 = null;
            List<TlsWord> path2 = null;
            if (issue instanceof BBAndPOVulnerability) {
                BBAndPOVulnerability vuln = (BBAndPOVulnerability) issue;
                TlsWord input1 = vuln.getFirstWord();
                TlsWord input2 = vuln.getSecondWord();
                List<TlsWord> pathPrefix = vuln.getPath();
                path1 = new LinkedList<>(pathPrefix);
                path1.add(input1);
                path2 = new LinkedList<>(pathPrefix);
                path2.add(input2);
                successor1 = AnalysisUtil.getStateReachedWithMessageSequence(stateMachine, path1);
                successor2 = AnalysisUtil.getStateReachedWithMessageSequence(stateMachine, path2);
                if (successor1 != successor2
                        && !AnalysisUtil.differingSuccessorIsMeaningful(
                                stateMachine, successor1, successor2)) {
                    filteredIssues.add(issue);
                }
            } else {
                continue;
            }
        }
        if (!filteredIssues.isEmpty()) {
            commonIssuesFound.add(CommonIssue.ASSUMED_CACHE_FILTER_ORACLE_BUG);
        }
        return filteredIssues;
    }
}
