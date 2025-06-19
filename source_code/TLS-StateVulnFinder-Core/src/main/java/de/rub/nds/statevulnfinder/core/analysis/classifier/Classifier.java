/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.analysis.classifier;

import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.algorithm.words.ResetConnectionWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import java.util.*;
import java.util.stream.Collectors;
import net.automatalib.automata.transducers.MealyMachine;
import net.automatalib.words.Alphabet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class Classifier {

    private static final Logger LOG = LogManager.getLogger();

    protected List<StateMachineIssue> determinedVulnerabilities;

    public static final int VULNERABILITY_CAP = 25;

    public abstract List<StateMachineIssue> getVulnerabilitiesOfClass(StateMachine machine);

    public static class PathNotFoundException extends Exception {
        public PathNotFoundException(String message) {
            super(message);
        }
    }

    /** Useful for breaking out of recursive call stacks. */
    protected static class FinishedException extends Exception {
        public FinishedException(String message) {
            super(message);
        }
    }

    /**
     * Returns the TLsWords that lead to the given node by using depth first search. We could use
     * Dijkstra but we do not need to find the shortest path, only any path.
     *
     * @param stateMachine The TlsStateMachine that will be analyzed
     * @param destNodes The node to which we calculate the path
     * @return The list of TlsWords that leads to the given node
     */
    public static List<TlsWord> getPathToNode(
            StateMachine stateMachine, Object[] destNodes, Object startNode, boolean allowReset)
            throws PathNotFoundException {
        MealyMachine machine = stateMachine.getMealyMachine();
        Alphabet alphabet = stateMachine.getAlphabet();
        List<TlsWord> inputs = new LinkedList<>(alphabet);
        ResetConnectionWord resetConnectionWord = new ResetConnectionWord();
        if (inputs.contains(resetConnectionWord)) {
            inputs.remove(resetConnectionWord);
            inputs.add(resetConnectionWord);
        }
        HashSet<Object> visited = new HashSet<>();
        Stack<TlsWord> messageStack = new Stack<>();
        List<TlsWord> path = new LinkedList<>();
        try {
            getPathToNodeInner(
                    machine, inputs, messageStack, visited, destNodes, startNode, path, allowReset);
        } catch (FinishedException e) {
            return path;
        }
        String nodeNames =
                Arrays.asList(destNodes).stream()
                        .map(Object::toString)
                        .collect(Collectors.joining("/"));
        throw new PathNotFoundException(
                "Could not find a path to " + nodeNames + " in the given state machine.");
    }

    public static List<TlsWord> getPathToNode(StateMachine stateMachine, Object... destNodes)
            throws PathNotFoundException {
        return getPathToNode(
                stateMachine, destNodes, stateMachine.getMealyMachine().getInitialState(), false);
    }

    public static List<TlsWord> getPathToNodeResetting(
            StateMachine stateMachine, Object startingState, Object... destNodes) {
        List<TlsWord> path = new LinkedList<>();
        boolean repeat = false;
        do {
            try {
                path = getPathToNode(stateMachine, destNodes, startingState, repeat);
            } catch (PathNotFoundException e) {
                repeat = !repeat;
            }
        } while (repeat && path.isEmpty());
        if (path.isEmpty() && !List.of(destNodes).contains(startingState)) {
            LOG.debug(
                    "Was unable to find a path between nodes {} and {}, returning empty path",
                    startingState,
                    destNodes);
        }
        return path;
    }

    /**
     * Inner function for iterative calls of getPathToNode
     *
     * @param machine The TlsStateMachine that will be analyzed
     * @param alphabet The alphabet of the TlsStateMachine
     * @param messageStack The current messageStack of TlsWords in the DFS algorithm
     * @param visited All nodes that have already been visited
     * @param destNodes The node to which we calculate the path
     * @param currNode The currently visited node
     * @param path The list in which we will safe the path
     * @throws FinishedException Thrown when a path has been found to break out of the recursive
     *     call stack
     */
    private static void getPathToNodeInner(
            MealyMachine machine,
            List<TlsWord> alphabet,
            Stack<TlsWord> messageStack,
            HashSet<Object> visited,
            Object[] destNodes,
            Object currNode,
            List<TlsWord> path,
            boolean allowReset)
            throws FinishedException {
        visited.add(currNode);
        if (Arrays.asList(destNodes).contains(currNode)) {
            path.clear();
            path.addAll(messageStack);
            // we throw an exception to exit the recursive call stack
            throw new FinishedException("Found path to node");
        }
        for (TlsWord tlsWord : alphabet) {
            if (tlsWord.getType() == TlsWordType.RESET_CONNECTION && !allowReset) {
                continue;
            }
            Object nextState = machine.getSuccessor(currNode, tlsWord);

            if (!visited.contains(nextState)) {
                messageStack.add((TlsWord) tlsWord);
                // only look a nodes we have not explored earlier
                getPathToNodeInner(
                        machine,
                        alphabet,
                        messageStack,
                        visited,
                        destNodes,
                        nextState,
                        path,
                        allowReset);
                messageStack.pop();
            }
        }
    }

    protected boolean checkTlsWordListIsPrefix(List<TlsWord> prefix, List<TlsWord> comparator) {
        if (prefix.size() > comparator.size()) {
            return false;
        }
        for (int i = 0; i < prefix.size(); i++) {
            if (!prefix.get(i).equals(comparator.get(i))) {
                return false;
            }
        }
        return true;
    }

    protected boolean checkClassListIsPrefix(List<Class> prefix, List<Class> comparator) {
        if (prefix.size() > comparator.size()) {
            return false;
        }
        for (int i = 0; i < prefix.size(); i++) {
            if (!prefix.get(i).equals(comparator.get(i))) {
                return false;
            }
        }
        return true;
    }

    protected boolean checkClassListsAreEqual(List<Class> classList1, List<Class> classList2) {
        if (classList1.size() != classList2.size()) {
            return false;
        }
        for (int i = 0; i < classList1.size(); i++) {
            if (!classList1.get(i).equals(classList2.get(i))) {
                return false;
            }
        }
        return true;
    }

    protected boolean checkOnlyAllowedClasses(List<Class> toCheck, List<Class> permittedClasses) {
        for (Class inspected : toCheck) {
            if (!permittedClasses.contains(inspected)) {
                return false;
            }
        }

        return true;
    }

    protected boolean checkTlsWordListsAreEqual(
            List<TlsWord> classList1, List<TlsWord> classList2) {
        if (classList1.size() != classList2.size()) {
            return false;
        }
        for (int i = 0; i < classList1.size(); i++) {
            if (!classList1.get(i).equals(classList2.get(i))) {
                return false;
            }
        }
        return true;
    }

    protected List<Class> convertToProtocolMessageTypeList(ResponseFingerprint fingerprint) {
        return convertToProtocolMessageTypeList(fingerprint.getMessageList());
    }

    protected List<Class> convertToProtocolMessageTypeList(List<ProtocolMessage> messages) {
        List<Class> typeList = new LinkedList<>();
        for (ProtocolMessage message : messages) {
            typeList.add(message.getClass());
        }
        return typeList;
    }

    protected List<Class> convertToProtocolMessageTypeList(Class... types) {
        return new ArrayList<>(Arrays.asList(types));
    }

    protected boolean checkPrefixAfterReset(Stack<TlsWord> messageStack, List<TlsWord> tlsWords) {
        List<TlsWord> wordsAfterReset = getWordsAfterReset(messageStack);
        if (wordsAfterReset != null) {
            return checkTlsWordListIsPrefix(wordsAfterReset, tlsWords);
        }
        return false;
    }

    protected List<TlsWord> getWordsAfterReset(Stack<TlsWord> messageStack) {
        List<Class> stackClasses =
                messageStack.stream().map(TlsWord::getClass).collect(Collectors.toList());
        if (stackClasses.contains(ResetConnectionWord.class)) {
            int lastIndex = stackClasses.lastIndexOf(ResetConnectionWord.class);

            return messageStack.stream().skip(lastIndex + 1).collect(Collectors.toList());
        }
        return null;
    }

    protected boolean checkEqualAfterReset(List<TlsWord> tlsWords, Stack<TlsWord> messageStack) {
        List<TlsWord> wordsAfterReset = getWordsAfterReset(messageStack);
        if (wordsAfterReset != null) {
            return checkTlsWordListsAreEqual(wordsAfterReset, tlsWords);
        }
        return false;
    }

    protected List<TlsWord> getPathOrEmptySequence(StateMachine stateMachine, Object state) {
        List<TlsWord> path;
        try {
            path = getPathToNode(stateMachine, state);
        } catch (PathNotFoundException e) {
            path = new LinkedList<>();
        }
        return path;
    }

    public List<StateMachineIssue> getDeterminedVulnerabilities() {
        return determinedVulnerabilities;
    }

    protected static List<TlsWord> reducePathIfPossible(
            List<TlsWord> messagesSent, StateMachine stateMachine, Object soughtTransition) {
        long connectionResets =
                messagesSent.stream()
                        .map(Object::getClass)
                        .filter(ResetConnectionWord.class::isAssignableFrom)
                        .count();
        // limited to paths with ResetConnection for now
        if (connectionResets > 0) {
            for (int preservedResets = 0; preservedResets < connectionResets; preservedResets++) {
                List<TlsWord> reducedMessagesSent = new LinkedList<>(messagesSent);
                reducedMessagesSent = reduceConnectionResets(preservedResets, messagesSent);
                if (reducedMessagesSent.size() < messagesSent.size()) {
                    Object currentState = stateMachine.getMealyMachine().getInitialState();
                    Object transition = null;
                    for (TlsWord input : reducedMessagesSent) {
                        transition =
                                stateMachine.getMealyMachine().getTransition(currentState, input);
                        currentState =
                                stateMachine.getMealyMachine().getSuccessor(currentState, input);
                    }
                    if (transition != null && transition.equals(soughtTransition)) {
                        return reducedMessagesSent;
                    }
                }
            }
        }

        // full input list is required
        return messagesSent;
    }

    private static List<TlsWord> reduceConnectionResets(
            int preservedResets, List<TlsWord> messageSequence) {
        int resetsFound = 0;
        for (int i = 0; i < messageSequence.size(); i++) {
            TlsWord input = messageSequence.get(i);
            if (input.getType() == TlsWordType.RESET_CONNECTION) {
                resetsFound += 1;
            }
            if (resetsFound > preservedResets) {
                if (i + 1 >= messageSequence.size()) {
                    // no input left after reset
                    return new LinkedList<>();
                }
                return messageSequence.subList(i + 1, messageSequence.size());
            }
        }
        throw new IllegalArgumentException(
                "Number of preserved resets exceeds number of present resets");
    }
}
