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
import de.rub.nds.statevulnfinder.core.algorithm.words.BleichenbacherWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.issue.DivergingBleichenbacherVulnerability;
import de.rub.nds.statevulnfinder.core.issue.SameStateBleichenbacherVulnerability;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import de.rub.nds.tlsscanner.core.vector.response.EqualityError;
import de.rub.nds.tlsscanner.core.vector.response.FingerprintChecker;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import net.automatalib.automata.transducers.MealyMachine;
import net.automatalib.words.Alphabet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BleichenbacherOracleClassifier extends Classifier {

    private static final Logger LOG = LogManager.getLogger();

    GraphDetails graphDetails;

    public BleichenbacherOracleClassifier(GraphDetails graphDetails) {
        this.graphDetails = graphDetails;
    }

    @Override
    public List<StateMachineIssue> getVulnerabilitiesOfClass(StateMachine stateMachine) {
        determinedVulnerabilities = new LinkedList<>();
        Alphabet alphabet = stateMachine.getAlphabet();
        List<TlsWord> bleichenbacherWords = new LinkedList<>();
        for (Iterator it = alphabet.iterator(); it.hasNext(); ) {
            TlsWord word = (TlsWord) it.next();
            if (word instanceof BleichenbacherWord) {
                bleichenbacherWords.add(word);
            }
        }
        determineVulnerabilities(bleichenbacherWords, stateMachine, determinedVulnerabilities);
        return determinedVulnerabilities;
    }

    private void determineVulnerabilities(
            List<TlsWord> bleichenbacherWords,
            StateMachine stateMachine,
            List<StateMachineIssue> vulnList) {
        MealyMachine machine = stateMachine.getMealyMachine();
        // find divering paths and/or nodes
        for (Object state : machine.getStates()) {
            for (TlsWord word : bleichenbacherWords) {
                Object referenceDestination = machine.getSuccessor(state, word);
                SulResponse referenceOutput = (SulResponse) machine.getOutput(state, word);
                for (TlsWord comparisonWord : bleichenbacherWords) {
                    if (comparisonWord.equals(word)) {
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
                            List<TlsWord> path =
                                    getPathToNodeResetting(
                                            stateMachine, machine.getInitialState(), state);

                            vulnList.add(
                                    new DivergingBleichenbacherVulnerability(
                                            state,
                                            referenceDestination,
                                            comparisonDestination,
                                            "Statemachine goes to different states depending on testvector",
                                            word,
                                            comparisonWord,
                                            path));

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
                                    new SameStateBleichenbacherVulnerability(
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
