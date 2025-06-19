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
import de.rub.nds.statevulnfinder.core.algorithm.words.ResetConnectionWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.server.analysis.transition.ServerTransitionAnalyzer;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class AnalysisUtil {

    public static String getStateDiffSuccessors(StateMachine machine, int s1, int s2) {
        StringBuilder builder = new StringBuilder();
        List<Object> stateList = new LinkedList<>(machine.getMealyMachine().getStates());
        Object state1 = stateList.get(s1);
        Object state2 = stateList.get(s2);
        for (TlsWord input : machine.getAlphabet()) {
            SulResponse response1 =
                    (SulResponse) machine.getMealyMachine().getOutput(state1, input);
            SulResponse response2 =
                    (SulResponse) machine.getMealyMachine().getOutput(state2, input);

            Object successor1 = machine.getMealyMachine().getSuccessor(state1, input);
            Object successor2 = machine.getMealyMachine().getSuccessor(state2, input);
            if (response1.equals(response2) && successor1 != successor2) {
                builder.append(
                                "s"
                                        + s1
                                        + "->"
                                        + "s"
                                        + stateList.indexOf(successor1)
                                        + " vs "
                                        + "s"
                                        + s2
                                        + "->"
                                        + "s"
                                        + stateList.indexOf(successor2)
                                        + " for "
                                        + input.toString()
                                        + " with "
                                        + response1)
                        .append("\n");
            }
        }
        return builder.toString();
    }

    public static String getStateDiffResponse(StateMachine machine, int s1, int s2) {
        StringBuilder builder = new StringBuilder();
        List<Object> stateList = new LinkedList<>(machine.getMealyMachine().getStates());
        Object state1 = stateList.get(s1);
        Object state2 = stateList.get(s2);
        for (TlsWord input : machine.getAlphabet()) {
            SulResponse response1 =
                    (SulResponse) machine.getMealyMachine().getOutput(state1, input);
            SulResponse response2 =
                    (SulResponse) machine.getMealyMachine().getOutput(state2, input);

            Object successor1 = machine.getMealyMachine().getSuccessor(state1, input);
            Object successor2 = machine.getMealyMachine().getSuccessor(state2, input);
            if (!response1.equals(response2) && successor1 == successor2) {
                builder.append(
                                input.toString()
                                        + ":\n\ts"
                                        + s1
                                        + ":"
                                        + response1.toString()
                                        + "\n\ts"
                                        + s2
                                        + ":"
                                        + response2.toString())
                        .append("\n");
            }
        }
        return builder.toString();
    }

    public static String getStateDiffBoth(StateMachine machine, int s1, int s2) {
        StringBuilder builder = new StringBuilder();
        List<Object> stateList = new LinkedList<>(machine.getMealyMachine().getStates());
        Object state1 = stateList.get(s1);
        Object state2 = stateList.get(s2);
        for (TlsWord input : machine.getAlphabet()) {
            SulResponse response1 =
                    (SulResponse) machine.getMealyMachine().getOutput(state1, input);
            SulResponse response2 =
                    (SulResponse) machine.getMealyMachine().getOutput(state2, input);

            Object successor1 = machine.getMealyMachine().getSuccessor(state1, input);
            Object successor2 = machine.getMealyMachine().getSuccessor(state2, input);
            if (!response1.equals(response2) && successor1 != successor2) {
                builder.append(
                                "For "
                                        + input.toString()
                                        + ":\n\ts"
                                        + s1
                                        + "->"
                                        + "s"
                                        + stateList.indexOf(successor1)
                                        + " with "
                                        + response1.toString()
                                        + "\n\ts"
                                        + s2
                                        + "->"
                                        + "s"
                                        + stateList.indexOf(successor2)
                                        + " with "
                                        + response2.toString())
                        .append("\n");
            }
        }
        return builder.toString();
    }

    public static String pathToString(StateMachine machine, List<TlsWord> path, Object startState) {
        StringBuilder builder = new StringBuilder();
        List<Object> stateList = new LinkedList<>(machine.getMealyMachine().getStates());
        int counter = 0;
        Object currentState = startState;
        for (TlsWord input : path) {
            counter += 1;
            Object nextState = machine.getMealyMachine().getSuccessor(currentState, input);
            SulResponse response =
                    (SulResponse) machine.getMealyMachine().getOutput(currentState, input);
            builder.append(
                    "\n"
                            + counter
                            + ". \t s"
                            + stateList.indexOf(currentState)
                            + " -> s"
                            + stateList.indexOf(nextState)
                            + " for "
                            + input
                            + " with "
                            + response);
            currentState = nextState;
        }
        return builder.toString();
    }

    public static boolean hasNoRegularSuccessor(
            StateMachine stateMachine, Object state, Set<Object> errorStates) {
        for (TlsWord input : stateMachine.getAlphabet()) {
            if (input.getType() != TlsWordType.RESET_CONNECTION) {
                Object successor = stateMachine.getMealyMachine().getSuccessor(state, input);
                if (!errorStates.contains(successor) && successor != state) {
                    return false;
                }
            }
        }
        return true;
    }

    public static boolean isTerminalState(
            StateMachine stateMachine, Object state, Set<Object> errorStates) {
        boolean hasNoRegularSuccessors = hasNoRegularSuccessor(stateMachine, state, errorStates);
        // Terminal states are not error states themselves
        return hasNoRegularSuccessors && !errorStates.contains(state);
    }

    public static String getMatchesStateMachineSymbol(
            StateMachine stateMachine,
            List<TlsWord> inputs,
            List<SulResponse> responses,
            int relevantIndex) {
        Object currentState = stateMachine.getMealyMachine().getInitialState();
        for (int i = 0; i < relevantIndex; i++) {
            TlsWord input = inputs.get(i);
            SulResponse expectedResponse =
                    (SulResponse) stateMachine.getMealyMachine().getOutput(currentState, input);
            currentState = stateMachine.getMealyMachine().getSuccessor(currentState, input);
            if (!expectedResponse.equals(responses.get(i)) && i == relevantIndex - 1) {
                return "!!";
            }
        }
        return "OK";
    }

    public static Object getStateReachedWithMessageSequence(
            StateMachine stateMachine, List<TlsWord> inputs) {
        return getStateReachedWithMessageSequence(stateMachine, inputs, 0);
    }

    public static Object getStateReachedWithMessageSequence(
            StateMachine stateMachine, List<TlsWord> inputs, int suffixInputsToIgnore) {
        if (inputs.size() - suffixInputsToIgnore < 0) {
            // sequence is too short
            return null;
        } else {
            Object currentState = stateMachine.getMealyMachine().getInitialState();
            for (int i = 0; i < inputs.size() - suffixInputsToIgnore; i++) {
                currentState =
                        stateMachine.getMealyMachine().getSuccessor(currentState, inputs.get(i));
            }
            return currentState;
        }
    }

    public static boolean trailingInputInSequenceOfType(
            TlsWordType type, List<TlsWord> messageSequence, int trailOffset) {
        return TlsWordType.effectivelyEquals(
                messageSequence.get(messageSequence.size() - (1 + trailOffset)).getType(), type);
    }

    public static boolean lastInputInSequenceOfType(
            TlsWordType type, List<TlsWord> messageSequence) {
        return trailingInputInSequenceOfType(type, messageSequence, 0);
    }

    public static SulResponse getLastResponse(List<TlsWord> inputs, StateMachine stateMachine) {
        Object previousState = getStateReachedWithMessageSequence(stateMachine, inputs, 1);
        SulResponse response =
                (SulResponse)
                        stateMachine
                                .getMealyMachine()
                                .getOutput(previousState, inputs.get(inputs.size() - 1));
        return response;
    }

    public static boolean lastResponseContainsMessages(
            List<TlsWord> inputs,
            StateMachine stateMachine,
            boolean exclusively,
            Set<Class<?>> messageClasses) {
        SulResponse lastResponse = getLastResponse(inputs, stateMachine);
        if (lastResponse.getResponseFingerprint() == null
                || lastResponse.getResponseFingerprint().getMessageList().isEmpty()) {
            return false;
        } else {
            if (exclusively) {
                return !lastResponse.getResponseFingerprint().getMessageList().stream()
                        .map(Object::getClass)
                        .filter(clazz -> !messageClasses.contains(clazz))
                        .findAny()
                        .isPresent();
            } else {
                List<Class<?>> classesRequired = new LinkedList<>(messageClasses);
                lastResponse.getResponseFingerprint().getMessageList().stream()
                        .map(Object::getClass)
                        .forEach(clazz -> classesRequired.remove(clazz));
                return classesRequired.isEmpty();
            }
        }
    }

    public static <T extends ProtocolMessage> List<T> getMessagesFromResponse(
            SulResponse response, Class<T> clazz) {
        if (response.getResponseFingerprint() != null
                && response.getResponseFingerprint().getMessageList() != null) {
            List<T> messages = new LinkedList<>();
            messages.addAll(
                    response.getResponseFingerprint().getMessageList().stream()
                            .filter(clazz::isInstance)
                            .map(clazz::cast)
                            .collect(Collectors.toList()));
            return messages;
        } else {
            return new LinkedList<>();
        }
    }

    public static boolean isNumeric(String string) {
        try {
            Integer.parseInt(string);
        } catch (NumberFormatException ex) {
            return false;
        }
        return true;
    }

    public static boolean stateCanBeReachedWith(
            StateMachine stateMachine, Object state, TlsWord... consideredInputs) {
        for (Object otherState : stateMachine.getMealyMachine().getStates()) {
            if (otherState == state) {
                continue;
            }
            for (TlsWord input : consideredInputs) {
                if (stateMachine.getMealyMachine().getSuccessor(otherState, input) == state) {
                    return true;
                }
            }
        }
        return false;
    }

    public static Set<Object> getDummyStates(StateMachine stateMachine) {
        Set<Object> statesReachableViaIllegalLearner = new HashSet<>();
        for (Object state : stateMachine.getMealyMachine().getStates()) {
            for (TlsWord input : stateMachine.getAlphabet()) {
                SulResponse output =
                        (SulResponse) stateMachine.getMealyMachine().getOutput(state, input);
                if (output.isIllegalTransitionFlag()) {
                    statesReachableViaIllegalLearner.add(
                            stateMachine.getMealyMachine().getSuccessor(state, input));
                }
            }
        }
        return statesReachableViaIllegalLearner;
    }

    public static int getFirstIllegalInputIndex(StateMachine stateMachine, List<TlsWord> inputs) {
        if (inputs == null || inputs.isEmpty()) {
            return -1; // No inputs to check
        }
        List<TlsWord> growingSequence = new LinkedList<>();
        for (int i = 0; i < inputs.size(); i++) {
            growingSequence.add(inputs.get(i));
            ServerTransitionAnalyzer analyzer =
                    new ServerTransitionAnalyzer(growingSequence, stateMachine);
            if (!analyzer.isBenignFlow()) {
                return i;
            }
        }
        return -1; // No illegal input found
    }

    /**
     * Majority votes bypassed the cache filter rules. Consequently, there may be paths that differ
     * solely due to an input that was not correctly replied with an IllegalLearnerTransition. This
     * method checks if there are differences beyond such cases.
     *
     * @param stateMachine
     * @param successor1 The first successor of a node
     * @param successor2 The second successor of the same node
     * @return True if there are different responses beyond IllegalLearnerTransitions at some point
     *     down the path, false otherwise
     */
    public static boolean differingSuccessorIsMeaningful(
            StateMachine stateMachine, Object successor1, Object successor2) {
        List<Object> processedStates = new LinkedList<>();
        return differingSuccessorIsMeaningfulInner(
                stateMachine, successor1, successor2, processedStates);
    }

    private static boolean differingSuccessorIsMeaningfulInner(
            StateMachine stateMachine,
            Object successor1,
            Object successor2,
            List<Object> processedStates) {
        Object statePath1 = successor1;
        Object statePath2 = successor2;
        processedStates.add(successor1);
        processedStates.add(successor2);
        if (deviatingResponsesNotSolelyDueToIllegalTransition(
                getDeviatingInputResponsePairs(stateMachine, statePath1, statePath2))) {
            // we found an observable difference which is not only 'IllegalTransition vs other'
            return true;
        }

        Map<TlsWord, List<Object>> deivatingSuccessorPairs =
                getDeviatingInputSuccessorPairs(stateMachine, statePath1, statePath2);
        for (List<Object> successorPairs : deivatingSuccessorPairs.values()) {
            if (!processedStates.contains(successorPairs.get(0))
                    && !processedStates.contains(successorPairs.get(1))) {
                if (differingSuccessorIsMeaningfulInner(
                        stateMachine,
                        successorPairs.get(0),
                        successorPairs.get(1),
                        processedStates)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean deviatingResponsesNotSolelyDueToIllegalTransition(
            Map<TlsWord, List<SulResponse>> deviatingResponses) {
        for (List<SulResponse> responses : deviatingResponses.values()) {
            if (responses.size() == 2) {
                int illegalTransitions = 0;
                for (SulResponse response : responses) {
                    if (response.isIllegalTransitionFlag()) {
                        illegalTransitions += 1;
                    }
                }
                if (illegalTransitions != 1) {
                    // avoid cases where one is illegal transition and the other isn't
                    return true;
                }
            }
        }
        return false;
    }

    public static Map<TlsWord, List<SulResponse>> getDeviatingInputResponsePairs(
            StateMachine stateMachine, Object state1, Object state2) {
        Map<TlsWord, List<SulResponse>> deviatingInputResponsePairs = new HashMap<>();
        for (TlsWord input : stateMachine.getAlphabet()) {
            SulResponse response1 =
                    (SulResponse) stateMachine.getMealyMachine().getOutput(state1, input);
            SulResponse response2 =
                    (SulResponse) stateMachine.getMealyMachine().getOutput(state2, input);
            if (!response1.equals(response2)) {
                deviatingInputResponsePairs.put(input, List.of(response1, response2));
            }
        }
        return deviatingInputResponsePairs;
    }

    public static Map<TlsWord, List<Object>> getDeviatingInputSuccessorPairs(
            StateMachine stateMachine, Object state1, Object state2) {
        Map<TlsWord, List<Object>> deviatingInputSuccessorPairs = new HashMap<>();
        for (TlsWord input : stateMachine.getAlphabet()) {
            Object successor1 = stateMachine.getMealyMachine().getSuccessor(state1, input);
            Object successor2 = stateMachine.getMealyMachine().getSuccessor(state2, input);
            if (successor1 != successor2) {
                deviatingInputSuccessorPairs.put(input, List.of(successor1, successor2));
            }
        }
        return deviatingInputSuccessorPairs;
    }

    public static List<TlsWord> getPathSinceReset(List<TlsWord> fullPath) {
        int firstAfterReset = fullPath.lastIndexOf(new ResetConnectionWord()) + 1;
        return new LinkedList<>(fullPath.subList(firstAfterReset, fullPath.size()));
    }

    public static List<Record> getAllRecords(StateMachine stateMachine) {
        List<Record> records = new LinkedList<>();
        for (Object state : stateMachine.getMealyMachine().getStates()) {
            for (TlsWord input : stateMachine.getAlphabet()) {
                SulResponse response =
                        (SulResponse) stateMachine.getMealyMachine().getOutput(state, input);
                if (!response.isIllegalTransitionFlag()
                        && response.getResponseFingerprint().getRecordList() != null) {
                    records.addAll(response.getResponseFingerprint().getRecordList());
                }
            }
        }
        return records;
    }

    public static <T extends ProtocolMessage> List<T> getAllMessagesOfClass(
            StateMachine stateMachine, Class<T> messageClass) {
        List<T> messages = new LinkedList<>();
        for (Object state : stateMachine.getMealyMachine().getStates()) {
            for (TlsWord input : stateMachine.getAlphabet()) {
                SulResponse response =
                        (SulResponse) stateMachine.getMealyMachine().getOutput(state, input);
                if (!response.isIllegalTransitionFlag()
                        && response.getResponseFingerprint() != null
                        && response.getResponseFingerprint().getMessageList() != null) {
                    messages.addAll(
                            response.getResponseFingerprint().getMessageList().stream()
                                    .filter(messageClass::isInstance)
                                    .map(messageClass::cast)
                                    .collect(Collectors.toList()));
                }
            }
        }
        return messages;
    }
}
