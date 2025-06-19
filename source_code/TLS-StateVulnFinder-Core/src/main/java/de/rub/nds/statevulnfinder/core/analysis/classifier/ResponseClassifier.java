/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2023 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.analysis.classifier;

import static de.rub.nds.statevulnfinder.core.analysis.classifier.Classifier.VULNERABILITY_CAP;

import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.analysis.classifier.subclassifier.ResponseSubclassifier;
import de.rub.nds.statevulnfinder.core.analysis.transitions.TransitionAnalyzer;
import de.rub.nds.statevulnfinder.core.analysis.transitions.TransitionAnalyzerProvider;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Stack;
import net.automatalib.words.Alphabet;

public class ResponseClassifier extends Classifier {

    private final ResponseSubclassifier[] subclassifiers;
    private final GraphDetails graphDetails;
    private final TransitionAnalyzerProvider transitionAnalyzerProvider;

    public ResponseClassifier(
            GraphDetails graphDetails,
            TransitionAnalyzerProvider transitionAnalyzerProvider,
            ResponseSubclassifier... subclassifiers) {
        this.subclassifiers = subclassifiers;
        this.graphDetails = graphDetails;
        this.transitionAnalyzerProvider = transitionAnalyzerProvider;
    }

    @Override
    public List<StateMachineIssue> getVulnerabilitiesOfClass(StateMachine machine) {
        determinedVulnerabilities = new LinkedList<>();
        Alphabet<TlsWord> alphabet = machine.getAlphabet();
        Object initialState = machine.getMealyMachine().getInitialState();
        HashSet<Object> visited = new HashSet<>();
        Stack<TlsWord> wordStack = new Stack<>();
        Map<ResponseSubclassifier, List<StateMachineIssue>> vulnerabilityMap = new HashMap<>();
        for (ResponseSubclassifier subclassifier : subclassifiers) {
            vulnerabilityMap.put(subclassifier, new LinkedList<>());
        }
        internalErrorInner(machine, alphabet, initialState, visited, wordStack, vulnerabilityMap);
        vulnerabilityMap
                .entrySet()
                .forEach(entry -> determinedVulnerabilities.addAll(entry.getValue()));
        return determinedVulnerabilities;
    }

    /**
     * Iteratively performs a depth first search on the given state machine. It gathers any found
     * internal errors the state machine responds with in the vulnerabilities list.
     *
     * @param machine MealyMachine that will be analyzed for cycles.
     * @param alphabet The alphabet of the MealyMachine. Usually TLS messages sent by the client.
     * @param state Current state in the depth first search algorithm.
     * @param visited A list of visited nodes, needed for depth first search.
     * @param wordStack The stack of tlsWords that leads to the current node.
     */
    private void internalErrorInner(
            StateMachine machine,
            Alphabet<TlsWord> alphabet,
            Object state,
            HashSet<Object> visited,
            Stack<TlsWord> wordStack,
            Map<ResponseSubclassifier, List<StateMachineIssue>> vulnerabilityMap) {
        visited.add(state);

        // iteratively call on all neighbors
        for (TlsWord tlsWord : alphabet) {
            Object neighbor = machine.getMealyMachine().getSuccessor(state, tlsWord);
            SulResponse sulResponse =
                    (SulResponse) machine.getMealyMachine().getOutput(state, tlsWord);
            wordStack.add(tlsWord);

            if (!sulResponse.isIllegalTransitionFlag()) {
                for (ResponseSubclassifier subclassifier : subclassifiers) {
                    TransitionAnalyzer transitionAnalyzer =
                            transitionAnalyzerProvider.getTransitionAnalyzer(wordStack, machine);
                    if (subclassifier.responseIndicatesVulnerability(
                                    sulResponse, transitionAnalyzer.isEffectivelyBenignFlow())
                            && vulnerabilityMap.get(subclassifier).size() < VULNERABILITY_CAP) {
                        vulnerabilityMap
                                .get(subclassifier)
                                .add(subclassifier.getVulnerability(wordStack));
                    }
                }
            }

            if (!visited.contains(neighbor)) {
                // only look a nodes we have not explored earlier
                internalErrorInner(
                        machine, alphabet, neighbor, visited, wordStack, vulnerabilityMap);
            }
            wordStack.pop();
        }
    }
}
