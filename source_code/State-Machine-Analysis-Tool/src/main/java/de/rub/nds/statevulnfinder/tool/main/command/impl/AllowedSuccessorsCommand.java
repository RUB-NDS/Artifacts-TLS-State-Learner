/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.main.command.impl;

import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextProperty;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.server.analysis.transition.ServerTransitionAnalyzer;
import de.rub.nds.statevulnfinder.tool.main.command.AbstractCommand;
import de.rub.nds.statevulnfinder.tool.main.command.CommandContext;
import de.rub.nds.statevulnfinder.tool.main.command.CommandUtil;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/** Command to determine allowed successor message types according to the TransitionAnalyzer. */
public class AllowedSuccessorsCommand extends AbstractCommand {

    @Override
    public String getName() {
        return "allowedSuccessors";
    }

    @Override
    public String[] getAliases() {
        return new String[] {"as"};
    }

    @Override
    public String getDescription() {
        return "Show allowed successor message types for a given message sequence";
    }

    @Override
    public String getUsage() {
        return "allowedSuccessors [indices]";
    }

    @Override
    protected boolean validateArguments(String[] args) {
        return true; // Allow empty arguments for initial state analysis
    }

    @Override
    protected void executeCommand(String[] args, CommandContext context) {
        StateMachine stateMachine = context.getStateMachine();
        List<TlsWord> inputsToSend = resolveQuerySequence(args, context);

        if (inputsToSend.isEmpty()) {
            LOG.info("Analyzing allowed successors for initial state (empty sequence)");
        } else {
            LOG.info(
                    "Analyzing allowed successors for sequence: '{}'",
                    inputsToSend.stream().map(Object::toString).collect(Collectors.joining(",")));
        }

        // Create a ServerTransitionAnalyzer with the message sequence
        ServerTransitionAnalyzer analyzer =
                new ServerTransitionAnalyzer(inputsToSend, stateMachine);

        // Check if the query represents an effectively benign flow
        boolean isEffectivelyBenign = analyzer.isEffectivelyBenignFlow();

        if (!isEffectivelyBenign) {
            LOG.info("Query is NOT an effectively benign flow.");

            // Find the longest prefix that is still benign
            List<TlsWord> longestBenignPrefix = findLongestBenignPrefix(inputsToSend, stateMachine);

            if (longestBenignPrefix.isEmpty()) {
                LOG.info("No benign prefix found - even empty sequence is not benign.");
                return;
            }

            LOG.info(
                    "Longest benign prefix ({} steps): '{}'",
                    longestBenignPrefix.size(),
                    longestBenignPrefix.stream()
                            .map(Object::toString)
                            .collect(Collectors.joining(",")));

            // Analyze the benign prefix instead
            analyzer = new ServerTransitionAnalyzer(longestBenignPrefix, stateMachine);
            LOG.info("Analyzing allowed successors for the benign prefix instead:");
            LOG.info("");
        }

        // Get the allowed successors and context properties (either for original query or benign
        // prefix)
        List<TlsWord> allowedSuccessors = analyzer.getAllowedSuccessors();
        Set<ContextProperty> activeProperties = analyzer.getContextPropertiesReached();

        // Display context properties first
        LOG.info("Active context properties ({} total):", activeProperties.size());
        if (activeProperties.isEmpty()) {
            LOG.info("  (none)");
        } else {
            activeProperties.stream()
                    .sorted((p1, p2) -> p1.name().compareTo(p2.name()))
                    .forEach(property -> LOG.info("  - {}", property.name()));
        }

        LOG.info(""); // Empty line for readability

        if (allowedSuccessors.isEmpty()) {
            LOG.info("No allowed successors found for this sequence.");
            return;
        }

        // Group allowed successors by type for better readability
        Map<TlsWordType, List<TlsWord>> groupedByType =
                allowedSuccessors.stream().collect(Collectors.groupingBy(TlsWord::getType));

        LOG.info("Allowed successor types ({} total):", allowedSuccessors.size());

        for (Map.Entry<TlsWordType, List<TlsWord>> entry : groupedByType.entrySet()) {
            TlsWordType type = entry.getKey();
            List<TlsWord> wordsOfType = entry.getValue();

            if (wordsOfType.size() == 1) {
                LOG.info("  - {} ({})", type.name(), wordsOfType.get(0).toString());
            } else {
                LOG.info("  - {} ({} variants):", type.name(), wordsOfType.size());
                for (TlsWord word : wordsOfType) {
                    LOG.info("    * {}", word.toString());
                }
            }
        }

        // Additional analysis information
        if (LOG.isDebugEnabled()) {
            LOG.debug("Is benign flow: {}", analyzer.isBenignFlow());
            LOG.debug("Is effectively benign flow: {}", analyzer.isEffectivelyBenignFlow());
        }
    }

    private List<TlsWord> resolveQuerySequence(String[] args, CommandContext context) {
        List<TlsWord> inputsToSend;
        if (args.length == 0) {
            // Empty query - analyze initial state
            inputsToSend = new LinkedList<>();
        } else if (args[0].startsWith("@")) {
            int sequenceIndex = Integer.parseInt(args[0].replace("@", ""));
            inputsToSend = getMessageSequence(sequenceIndex, context);
        } else {
            inputsToSend = CommandUtil.parseInputs(args, context.getStateMachine());
        }
        return inputsToSend;
    }

    private List<TlsWord> getMessageSequence(int index, CommandContext context) {
        if (index >= 0 && index < context.getRecentMessageSequences().size()) {
            return context.getRecentMessageSequences().get(index);
        }
        LOG.warn("Invalid message sequence index {}. Returning empty path.", index);
        return new LinkedList<>();
    }

    /**
     * Finds the longest prefix of the input sequence that is still considered effectively benign.
     * Uses binary search approach for efficiency.
     *
     * @param inputSequence the full input sequence to analyze
     * @param stateMachine the state machine to use for analysis
     * @return the longest benign prefix, or empty list if no prefix is benign
     */
    private List<TlsWord> findLongestBenignPrefix(
            List<TlsWord> inputSequence, StateMachine stateMachine) {
        if (inputSequence.isEmpty()) {
            return new LinkedList<>();
        }

        // Check if empty sequence is benign (should be)
        ServerTransitionAnalyzer emptyAnalyzer =
                new ServerTransitionAnalyzer(new LinkedList<>(), stateMachine);
        if (!emptyAnalyzer.isEffectivelyBenignFlow()) {
            return new LinkedList<>();
        }

        // Binary search for the longest benign prefix
        int left = 0;
        int right = inputSequence.size();
        List<TlsWord> longestBenignPrefix = new LinkedList<>();

        while (left <= right) {
            int mid = (left + right) / 2;
            List<TlsWord> candidatePrefix = new LinkedList<>(inputSequence.subList(0, mid));

            ServerTransitionAnalyzer prefixAnalyzer =
                    new ServerTransitionAnalyzer(candidatePrefix, stateMachine);

            if (prefixAnalyzer.isEffectivelyBenignFlow()) {
                // This prefix is benign, try a longer one
                longestBenignPrefix = new LinkedList<>(candidatePrefix);
                left = mid + 1;
            } else {
                // This prefix is not benign, try a shorter one
                right = mid - 1;
            }
        }

        return longestBenignPrefix;
    }
}
