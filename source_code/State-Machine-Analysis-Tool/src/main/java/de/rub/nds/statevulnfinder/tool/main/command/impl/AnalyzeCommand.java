/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.main.command.impl;

import de.rub.nds.statevulnfinder.core.algorithm.words.PaddingOracleWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.Analyzer;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.issue.DivergingCCSVulnerability;
import de.rub.nds.statevulnfinder.core.issue.DivergingPaddingOracleVulnerability;
import de.rub.nds.statevulnfinder.core.issue.IgnoredInputIssue;
import de.rub.nds.statevulnfinder.core.issue.InternalErrorIssue;
import de.rub.nds.statevulnfinder.core.issue.LeavingHappyFlowIssue;
import de.rub.nds.statevulnfinder.core.issue.NoHappyFlowIssue;
import de.rub.nds.statevulnfinder.core.issue.SameStatePaddingOracleVulnerability;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import de.rub.nds.statevulnfinder.core.issue.UnwantedHappyFlowVulnerability;
import de.rub.nds.statevulnfinder.server.extraction.TlsServerSulProvider;
import de.rub.nds.statevulnfinder.tool.analysis.AnalysisUtil;
import de.rub.nds.statevulnfinder.tool.main.command.AbstractCommand;
import de.rub.nds.statevulnfinder.tool.main.command.CommandContext;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/** Command to run analysis on the loaded state machine. */
public class AnalyzeCommand extends AbstractCommand {

    @Override
    public String getName() {
        return "analyze";
    }

    @Override
    public String getDescription() {
        return "Run analysis on the loaded state machine";
    }

    @Override
    public String getUsage() {
        return "analyze";
    }

    @Override
    protected boolean validateArguments(String[] args) {
        return args.length == 0 || args.length == 1;
    }

    @Override
    protected void executeCommand(String[] args, CommandContext context) {
        GraphDetails graphDetails = new GraphDetails();
        context.setGraphDetails(graphDetails);

        Analyzer analyzer = new TlsServerSulProvider().getAnalyzer(graphDetails);
        List<StateMachineIssue> foundIssues =
                analyzer.findVulnerabilities(context.getStateMachine());
        context.setFoundVulnerabilities(foundIssues);

        // Skip output if in silent mode
        if (context.isSilentMode()) {
            return;
        }

        if (args.length > 0 && args[0].equals("-d")) {
            detailedPrintIssues(foundIssues, context);
        } else {
            prettyPrintIssues(foundIssues, context);
        }
    }

    private void prettyPrintIssues(List<StateMachineIssue> issues, CommandContext context) {
        if (issues.isEmpty()) {
            LOG.info("No issues found.");
        } else {
            LOG.info("Identified issues:\n------------------------------------");
            prettyPrintDivergingCcsIssues(issues, context);
            prettyPrintUnwantedHappyFlowIssues(issues, context);
            prettyPrintLeavingHappyFlowIssues(issues, context);
            prettyPrintPaddingOracleIssues(issues, context);
            prettyPrintIgnoredMessages(issues, context);
            prettyPrintInternalErrors(issues, context);
            prettyPrintNoHappyFlowIssues(issues, context);

            if (!issues.isEmpty()) {
                LOG.info("\nThe following uncategorized other issues were found:");
                issues.forEach(
                        issue ->
                                LOG.info(
                                        "- {} - (message sequence cached as @{})",
                                        issue,
                                        issue.getPath()));
            }
        }
        LOG.info("\nUse  'analyze -d' for detailed output.");
    }

    private void prettyPrintInternalErrors(List<StateMachineIssue> issues, CommandContext context) {
        List<InternalErrorIssue> internalErrors =
                issues.stream()
                        .filter(issue -> issue instanceof InternalErrorIssue)
                        .map(issue -> (InternalErrorIssue) issue)
                        .collect(Collectors.toList());
        issues.removeAll(internalErrors);
        if (!internalErrors.isEmpty()) {
            LOG.info("\nSUL sent Internal Error alerts:");

            internalErrors.forEach(
                    error ->
                            LOG.error(
                                    "- In state {} for input {}",
                                    AnalysisUtil.getStateReachedWithMessageSequence(
                                            context.getStateMachine(),
                                            error.getPath().subList(0, error.getPath().size() - 1)),
                                    error.getPath().get(error.getPath().size() - 1).getType()));
        }
    }

    private void prettyPrintPaddingOracleIssues(
            List<StateMachineIssue> issues, CommandContext context) {
        // Handle SameStatePaddingOracleVulnerability
        List<SameStatePaddingOracleVulnerability> sameStatePOIssues =
                issues.stream()
                        .filter(issue -> issue instanceof SameStatePaddingOracleVulnerability)
                        .map(issue -> (SameStatePaddingOracleVulnerability) issue)
                        .collect(Collectors.toList());
        issues.removeAll(sameStatePOIssues);

        if (!sameStatePOIssues.isEmpty()) {
            LOG.info("\nSUL shows padding oracle behavior (same state, different responses):");

            // Group by source state and response patterns
            Map<String, Map<String, List<PaddingOracleWord>>> responsePatterns = new HashMap<>();

            for (SameStatePaddingOracleVulnerability issue : sameStatePOIssues) {
                String state =
                        String.valueOf(
                                AnalysisUtil.getStateReachedWithMessageSequence(
                                        context.getStateMachine(), issue.getPath()));

                responsePatterns.putIfAbsent(state, new HashMap<>());
                Map<String, List<PaddingOracleWord>> statePatterns = responsePatterns.get(state);

                String firstResponse = issue.getFirstEdge().toString();
                statePatterns.putIfAbsent(firstResponse, new ArrayList<>());
                statePatterns.get(firstResponse).add((PaddingOracleWord) issue.getFirstWord());

                String secondResponse = issue.getSecondEdge().toString();
                statePatterns.putIfAbsent(secondResponse, new ArrayList<>());
                statePatterns.get(secondResponse).add((PaddingOracleWord) issue.getSecondWord());
            }

            for (Map.Entry<String, Map<String, List<PaddingOracleWord>>> stateEntry :
                    responsePatterns.entrySet()) {
                LOG.error("- In state {}", stateEntry.getKey());
                for (Map.Entry<String, List<PaddingOracleWord>> patternEntry :
                        stateEntry.getValue().entrySet()) {
                    LOG.error("    Response pattern: {}", patternEntry.getKey());
                    LOG.error(
                            "    Triggered by: {}",
                            patternEntry.getValue().stream()
                                    .map(PaddingOracleWord::toString)
                                    .distinct()
                                    .collect(Collectors.joining(", ")));
                }
            }
        }

        List<DivergingPaddingOracleVulnerability> divergingPOIssues =
                issues.stream()
                        .filter(issue -> issue instanceof DivergingPaddingOracleVulnerability)
                        .map(issue -> (DivergingPaddingOracleVulnerability) issue)
                        .collect(Collectors.toList());
        issues.removeAll(divergingPOIssues);

        if (!divergingPOIssues.isEmpty()) {
            LOG.info("\nSUL shows padding oracle behavior (diverging states):");

            // Group by source state and successor states
            Map<String, Map<String, List<PaddingOracleWord>>> stateTransitions = new HashMap<>();

            for (DivergingPaddingOracleVulnerability issue : divergingPOIssues) {
                String sourceState =
                        String.valueOf(
                                AnalysisUtil.getStateReachedWithMessageSequence(
                                        context.getStateMachine(), issue.getPath()));

                stateTransitions.putIfAbsent(sourceState, new HashMap<>());
                Map<String, List<PaddingOracleWord>> transitions =
                        stateTransitions.get(sourceState);

                // Since target nodes are not accessible via public methods, we'll use the
                // toString() output
                // which contains the information we need
                String issueString = issue.toString();

                // Extract firstTargetNode and secondTargetNode from the toString representation
                // Format: "DivergingPaddingOracleVulnerability{sourceNode=X, firstTargetNode=Y,
                // secondTargetNode=Z, ...}"
                String firstTarget = extractNodeFromString(issueString, "firstTargetNode=");
                String secondTarget = extractNodeFromString(issueString, "secondTargetNode=");

                transitions.putIfAbsent(firstTarget, new ArrayList<>());
                transitions.get(firstTarget).add((PaddingOracleWord) issue.getFirstWord());

                transitions.putIfAbsent(secondTarget, new ArrayList<>());
                transitions.get(secondTarget).add((PaddingOracleWord) issue.getSecondWord());
            }

            // Print the grouped results
            for (Map.Entry<String, Map<String, List<PaddingOracleWord>>> stateEntry :
                    stateTransitions.entrySet()) {
                LOG.error("- In state {}", stateEntry.getKey());
                for (Map.Entry<String, List<PaddingOracleWord>> transitionEntry :
                        stateEntry.getValue().entrySet()) {
                    LOG.error(
                            "    To state {}: triggered by {}",
                            transitionEntry.getKey(),
                            transitionEntry.getValue().stream()
                                    .map(PaddingOracleWord::toString)
                                    .distinct()
                                    .collect(Collectors.joining(", ")));
                }
            }
        }
    }

    private void prettyPrintDivergingCcsIssues(
            List<StateMachineIssue> issues, CommandContext context) {
        // div CCS issues are a side-result of other issues which are already printed
        // they may be of interest for debugging but we exclude them for now
        issues.removeIf(issue -> issue instanceof DivergingCCSVulnerability);
    }

    private void prettyPrintNoHappyFlowIssues(
            List<StateMachineIssue> issues, CommandContext context) {
        List<NoHappyFlowIssue> noHappyFlowIssues =
                issues.stream()
                        .filter(issue -> issue instanceof NoHappyFlowIssue)
                        .map(issue -> (NoHappyFlowIssue) issue)
                        .collect(Collectors.toList());
        issues.removeAll(noHappyFlowIssues);
        List<NoHappyFlowIssue> nonAppDataRelatedIssues =
                noHappyFlowIssues.stream()
                        .filter(
                                issue ->
                                        !issue.getPath()
                                                .get(issue.getPath().size() - 1)
                                                .getType()
                                                .isAppData())
                        .collect(Collectors.toList());
        boolean closesForAppData = !(nonAppDataRelatedIssues.size() == noHappyFlowIssues.size());
        if (!nonAppDataRelatedIssues.isEmpty()) {
            LOG.info("\nSUL rejected benign message sequences:");

            nonAppDataRelatedIssues.forEach(
                    error ->
                            LOG.error(
                                    "- In state {} for input {}",
                                    AnalysisUtil.getStateReachedWithMessageSequence(
                                            context.getStateMachine(),
                                            error.getPath().subList(0, error.getPath().size() - 1)),
                                    error.getPath().get(error.getPath().size() - 1).getType()));
        }
        if (closesForAppData) {
            LOG.info(
                    "Note: SUL appears to close the connection in response to our application data.");
        }
    }

    private void prettyPrintIgnoredMessages(
            List<StateMachineIssue> issues, CommandContext context) {
        List<IgnoredInputIssue> ignoredInputErrors =
                issues.stream()
                        .filter(issue -> issue instanceof IgnoredInputIssue)
                        .map(issue -> (IgnoredInputIssue) issue)
                        .collect(Collectors.toList());
        issues.removeAll(ignoredInputErrors);
        if (!ignoredInputErrors.isEmpty()) {
            LOG.info("\nSUL ignored illegal inputs (no state change):");

            ignoredInputErrors.forEach(
                    error ->
                            LOG.error(
                                    "- In state {} for input {}",
                                    AnalysisUtil.getStateReachedWithMessageSequence(
                                            context.getStateMachine(),
                                            error.getPath().subList(0, error.getPath().size() - 1)),
                                    error.getPath().get(error.getPath().size() - 1).getType()));
        }
    }

    private void prettyPrintLeavingHappyFlowIssues(
            List<StateMachineIssue> issues, CommandContext context) {
        List<LeavingHappyFlowIssue> leavingHappyFlowError =
                issues.stream()
                        .filter(issue -> issue instanceof LeavingHappyFlowIssue)
                        .map(issue -> (LeavingHappyFlowIssue) issue)
                        .collect(Collectors.toList());
        issues.removeAll(leavingHappyFlowError);
        if (!leavingHappyFlowError.isEmpty()) {
            LOG.info("\nSUL left the happy flow without reaching error state for illegal inputs:");

            leavingHappyFlowError.forEach(
                    error ->
                            LOG.error(
                                    "- In state {} for input {}\n     Full message sequence: {}",
                                    AnalysisUtil.getStateReachedWithMessageSequence(
                                            context.getStateMachine(),
                                            error.getPath().subList(0, error.getPath().size() - 1)),
                                    error.getPath().get(error.getPath().size() - 1).getType(),
                                    getHighlightedMessageSequence(
                                            error.getPath(), error.getPath().size() - 1)));
        }
    }

    private void prettyPrintUnwantedHappyFlowIssues(
            List<StateMachineIssue> issues, CommandContext context) {
        List<UnwantedHappyFlowVulnerability> unwantedHappyFlowIssues =
                issues.stream()
                        .filter(issue -> issue instanceof UnwantedHappyFlowVulnerability)
                        .map(issue -> (UnwantedHappyFlowVulnerability) issue)
                        .collect(Collectors.toList());
        issues.removeAll(unwantedHappyFlowIssues);
        if (!unwantedHappyFlowIssues.isEmpty()) {
            LOG.info("\nSUL accepts invalid message paths which lead back to the happyflow:");

            unwantedHappyFlowIssues.forEach(
                    issue ->
                            LOG.error(
                                    "- Message sequence {}",
                                    getHighlightedMessageSequence(
                                            issue.getPath(),
                                            AnalysisUtil.getFirstIllegalInputIndex(
                                                    context.getStateMachine(), issue.getPath()))));
        }
    }

    private void detailedPrintIssues(List<StateMachineIssue> foundIssues, CommandContext context) {
        if (foundIssues.isEmpty()) {
            LOG.info("No issues found.");
        } else {
            LOG.info("Identified issues:");
            foundIssues.stream()
                    .forEach(
                            issue -> {
                                LOG.info(
                                        "- {} - (message sequence cached as @{})",
                                        issue.toString(),
                                        context.getRecentMessageSequences().size());
                                context.getRecentMessageSequences().add(issue.getPath());
                            });
            LOG.info(
                    "\nYou can simulate message sequences using 'sq <path>' or using the cached path e.g 'sq @0'.");
        }
    }

    private String getHighlightedMessageSequence(
            List<TlsWord> messageSequence, int indexToHighligh) {
        // Print comma separated, highlight specified index using string builder
        StringBuilder highlightedSequence = new StringBuilder();
        for (int i = 0; i < messageSequence.size(); i++) {
            if (i == indexToHighligh) {
                highlightedSequence
                        .append("**")
                        .append(messageSequence.get(i).toShortString())
                        .append("**");
            } else {
                highlightedSequence.append(messageSequence.get(i).toShortString());
            }
            if (i < messageSequence.size() - 1) {
                highlightedSequence.append(", ");
            }
        }
        return highlightedSequence.toString();
    }

    private String extractNodeFromString(String issueString, String nodeKey) {
        int startIndex = issueString.indexOf(nodeKey);
        if (startIndex == -1) {
            return "Unknown";
        }
        startIndex += nodeKey.length();
        int endIndex = issueString.indexOf(',', startIndex);
        if (endIndex == -1) {
            endIndex = issueString.indexOf('}', startIndex);
        }
        if (endIndex == -1) {
            return "Unknown";
        }
        return issueString.substring(startIndex, endIndex).trim();
    }
}
