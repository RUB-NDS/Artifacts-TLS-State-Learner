/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2023 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.analysis.classifier;

import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.algorithm.words.ChangeCipherSpecWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.DummyChangeCipherSpecWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.core.issue.DivergingCCSVulnerability;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import java.util.LinkedList;
import java.util.List;
import net.automatalib.automata.transducers.MealyMachine;
import net.automatalib.words.Alphabet;

/**
 * Identifies states from which sending a CCS without enabling encryption leads to a different
 * behavior than with enabled encryption.
 */
public class CCSClassifier extends Classifier {

    private final GraphDetails graphDetails;

    public CCSClassifier(GraphDetails graphDetails) {
        this.graphDetails = graphDetails;
    }

    @Override
    public List<StateMachineIssue> getVulnerabilitiesOfClass(StateMachine machine) {
        determinedVulnerabilities = new LinkedList<>();
        Alphabet alphabet = machine.getAlphabet();
        if (!graphDetails.getBenignStateInfoMap().isEmpty()
                && alphabet.contains(new ChangeCipherSpecWord())
                && alphabet.contains(new DummyChangeCipherSpecWord())) {
            for (Object state : machine.getMealyMachine().getStates()) {
                evaluateState(machine, state, determinedVulnerabilities);
            }
        }
        return determinedVulnerabilities;
    }

    private void evaluateState(
            StateMachine machine, Object state, List<StateMachineIssue> vulnerabilities) {
        MealyMachine mealyMachine = machine.getMealyMachine();
        TlsWord realCcs = new ChangeCipherSpecWord();
        TlsWord dummyCcs = new DummyChangeCipherSpecWord();
        Object successorRealCcs = mealyMachine.getSuccessor(state, realCcs);
        Object successorDummyCcs = mealyMachine.getSuccessor(state, dummyCcs);
        // we exclude differences if the real successor is the benign CCS state since we know there
        // must be a difference
        // we also assume that an ignored ccs will result in a difference
        if (successorDummyCcs != state
                && successorRealCcs != successorDummyCcs
                && (!graphDetails.hasStateInfo(successorRealCcs)
                        || !graphDetails
                                .getStateInfo(successorRealCcs)
                                .getNames()
                                .contains(TlsWordType.CCS.name()))) {
            List<TlsWord> path = getPathOrEmptySequence(machine, state);
            vulnerabilities.add(
                    new DivergingCCSVulnerability(
                            state,
                            successorRealCcs,
                            successorDummyCcs,
                            "Statemachine goes to different states depending on CCS behavior",
                            realCcs,
                            dummyCcs,
                            path));
        }
    }
}
