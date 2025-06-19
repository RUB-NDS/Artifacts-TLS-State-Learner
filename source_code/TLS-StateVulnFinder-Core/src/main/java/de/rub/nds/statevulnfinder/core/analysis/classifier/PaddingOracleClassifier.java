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
import de.rub.nds.statevulnfinder.core.algorithm.words.PaddingOracleWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.issue.DivergingPaddingOracleVulnerability;
import de.rub.nds.statevulnfinder.core.issue.SameStatePaddingOracleVulnerability;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import de.rub.nds.tlsscanner.core.vector.response.EqualityError;
import de.rub.nds.tlsscanner.core.vector.response.FingerprintChecker;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import net.automatalib.automata.transducers.MealyMachine;
import net.automatalib.words.Alphabet;

public class PaddingOracleClassifier extends Classifier {

    GraphDetails graphDetails;

    // holds all edges which have a diverging padding oracle message flow
    List<Object> divergingEdges = new LinkedList<>();

    public PaddingOracleClassifier(GraphDetails graphDetails) {
        this.graphDetails = graphDetails;
    }

    @Override
    public List<StateMachineIssue> getVulnerabilitiesOfClass(StateMachine stateMachine) {
        determinedVulnerabilities = new LinkedList<>();

        Alphabet alphabet = stateMachine.getAlphabet();
        List<PaddingOracleWord> paddingOracleWords = new LinkedList<>();
        for (Iterator it = alphabet.iterator(); it.hasNext(); ) {
            TlsWord word = (TlsWord) it.next();
            if (word instanceof PaddingOracleWord) {
                paddingOracleWords.add((PaddingOracleWord) word);
            }
        }
        determineVulnerabilities(paddingOracleWords, stateMachine, determinedVulnerabilities);
        return determinedVulnerabilities;
    }

    private void determineVulnerabilities(
            List<PaddingOracleWord> paddingOracleWords,
            StateMachine stateMachine,
            List<StateMachineIssue> vulnList) {
        MealyMachine machine = stateMachine.getMealyMachine();
        for (Object state : machine.getStates()) {
            for (PaddingOracleWord word : paddingOracleWords) {
                Object referenceDestination = machine.getSuccessor(state, word);
                SulResponse referenceOutput = (SulResponse) machine.getOutput(state, word);
                if (referenceOutput.isIllegalTransitionFlag()) {
                    continue;
                }
                for (PaddingOracleWord comparisonWord : paddingOracleWords) {
                    if (comparisonWord.equals(word)
                            || !word.getProtocolMessageType()
                                    .equals(comparisonWord.getProtocolMessageType())) {
                        continue;
                    }
                    Object comparisonDestination = machine.getSuccessor(state, comparisonWord);
                    if (comparisonDestination != null) {
                        SulResponse comparisonOutput =
                                (SulResponse) machine.getOutput(state, comparisonWord);
                        if (comparisonOutput.isIllegalTransitionFlag()) {
                            continue;
                        }
                        if (!comparisonDestination.equals(referenceDestination)) {
                            // Edges dont point to same node
                            // get Path to node that triggers the vulnerability
                            List<TlsWord> path =
                                    getPathToNodeResetting(
                                            stateMachine, machine.getInitialState(), state);
                            // return vulnerability
                            vulnList.add(
                                    new DivergingPaddingOracleVulnerability(
                                            state,
                                            referenceDestination,
                                            comparisonDestination,
                                            "Statemachine goes to different states depending on testvector",
                                            word,
                                            comparisonWord,
                                            path));
                            divergingEdges.add(machine.getTransition(state, comparisonWord));
                            if (vulnList.size() >= VULNERABILITY_CAP) {
                                return;
                            }
                        } else if (FingerprintChecker.checkEquality(
                                        referenceOutput.getResponseFingerprint(),
                                        comparisonOutput.getResponseFingerprint())
                                != EqualityError.NONE) {
                            // get Path to node that triggers the vulnerability
                            List<TlsWord> path =
                                    getPathToNodeResetting(
                                            stateMachine, machine.getInitialState(), state);
                            path.add(comparisonWord);
                            // return vulnerability
                            vulnList.add(
                                    new SameStatePaddingOracleVulnerability(
                                            state,
                                            referenceDestination,
                                            referenceOutput.getResponseFingerprint(),
                                            comparisonOutput.getResponseFingerprint(),
                                            FingerprintChecker.checkEquality(
                                                    referenceOutput.getResponseFingerprint(),
                                                    comparisonOutput.getResponseFingerprint()),
                                            "Statemachine goes to same state but with different ResponseFingerprint (unencrypted)",
                                            word,
                                            comparisonWord,
                                            path));
                            if (vulnList.size() >= VULNERABILITY_CAP) {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}
