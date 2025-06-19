/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.main.command;

import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextProperty;
import de.rub.nds.statevulnfinder.tool.analysis.AnalysisUtil;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

/** Utility methods for command implementations. */
public class CommandUtil {

    /**
     * Parse a state index from string.
     *
     * @param stateStr State string
     * @return State index, or -1 if invalid
     */
    public static int parseState(String stateStr) {
        try {
            return Integer.parseInt(stateStr);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /**
     * Check if a state index is valid.
     *
     * @param stateIndex State index
     * @param stateMachine State machine
     * @return true if valid
     */
    public static boolean isValidState(int stateIndex, StateMachine stateMachine) {
        return stateIndex >= 0 && stateIndex < stateMachine.getMealyMachine().getStates().size();
    }

    /**
     * Get state object by index.
     *
     * @param index State index
     * @param stateMachine State machine
     * @return State object
     */
    public static Object getStateByIndex(int index, StateMachine stateMachine) {
        List<Object> stateList = new LinkedList<>(stateMachine.getMealyMachine().getStates());
        return stateList.get(index);
    }

    /**
     * Parse inputs from command arguments.
     *
     * @param args Command arguments containing input indices or names
     * @param stateMachine State machine containing the alphabet
     * @return List of TlsWord inputs
     */
    public static List<TlsWord> parseInputs(String[] args, StateMachine stateMachine) {
        List<TlsWord> inputsToSend = new LinkedList<>();
        List<TlsWord> alphabet = new LinkedList<>(stateMachine.getAlphabet());

        // Handle comma-separated or space-separated inputs
        List<String> inputParts = new LinkedList<>();
        for (String arg : args) {
            if (arg.contains(",")) {
                inputParts.addAll(Arrays.asList(arg.split(",\\s*")));
            } else {
                inputParts.add(arg);
            }
        }

        // Filter out boolean flags at the end
        while (!inputParts.isEmpty()) {
            String lastPart = inputParts.get(inputParts.size() - 1);
            if (lastPart.equalsIgnoreCase("true") || lastPart.equalsIgnoreCase("false")) {
                inputParts.remove(inputParts.size() - 1);
            } else {
                break;
            }
        }

        for (String part : inputParts) {
            final String trimmedPart = part.trim().replaceAll(",$", "");

            if (AnalysisUtil.isNumeric(trimmedPart)) {
                // Parse as index
                try {
                    int index = Integer.parseInt(trimmedPart);
                    if (index >= 0 && index < alphabet.size()) {
                        inputsToSend.add(alphabet.get(index));
                    }
                } catch (NumberFormatException ignored) {
                }
            } else {
                // Match by name
                Optional<TlsWord> matchingWord =
                        alphabet.stream()
                                .filter(word -> word.toString().equalsIgnoreCase(trimmedPart))
                                .findFirst();
                matchingWord.ifPresent(inputsToSend::add);
            }
        }

        return inputsToSend;
    }

    /**
     * Resolve state quick symbol for display.
     *
     * @param state State object
     * @param stateMachine State machine
     * @param graphDetails Graph analysis details
     * @return Quick symbol string (E for Error State, T for Terminal State, B for Bleichenbacher
     *     Path, R for Resumable)
     */
    public static String resolveStateQuickSymbol(
            Object state, StateMachine stateMachine, GraphDetails graphDetails) {
        String quickSymbol = "";

        if (AnalysisUtil.hasNoRegularSuccessor(
                stateMachine, state, graphDetails.getErrorStates())) {
            if (graphDetails.getErrorStates().contains(state)
                    || graphDetails.getIllegalTransitionLearnerState() == state) {
                quickSymbol = "E";
            } else {
                quickSymbol = "T";
            }
        } else {
            quickSymbol = " ";
        }

        if (graphDetails.getBenignStateInfoMap().containsKey(state)
                && graphDetails
                        .getBenignStateInfoMap()
                        .get(state)
                        .getContextPropertiesWhenReached()
                        .contains(ContextProperty.BLEICHENBACHER_PATH)) {
            quickSymbol = quickSymbol + "B";
        } else {
            quickSymbol = quickSymbol + " ";
        }

        if (graphDetails.getBenignStateInfoMap().containsKey(state)
                && (graphDetails
                                .getBenignStateInfoMap()
                                .get(state)
                                .getContextPropertiesWhenReached()
                                .contains(ContextProperty.CAN_RESUME_CORRECTLY_TLS12)
                        || graphDetails
                                .getBenignStateInfoMap()
                                .get(state)
                                .getContextPropertiesWhenReached()
                                .contains(ContextProperty.CAN_RESUME_CORRECTLY_TLS13))) {
            quickSymbol = quickSymbol + "R";
        } else {
            quickSymbol = quickSymbol + " ";
        }

        return quickSymbol;
    }
}
