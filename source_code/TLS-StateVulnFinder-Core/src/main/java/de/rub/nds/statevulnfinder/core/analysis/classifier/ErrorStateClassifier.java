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
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.core.issue.IgnoredInputIssue;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class ErrorStateClassifier extends Classifier {

    private final GraphDetails graphDetails;

    public ErrorStateClassifier(GraphDetails graphDetails) {
        this.graphDetails = graphDetails;
    }

    @Override
    public List<StateMachineIssue> getVulnerabilitiesOfClass(StateMachine machine) {
        determinedVulnerabilities = new LinkedList<>();
        Set<Object> determinedErrorStates = new HashSet<>();
        Object determinedDummyState = null;

        // get all states that effectively trap us, we assume these are error states
        for (Object state : machine.getMealyMachine().getStates()) {
            if (isTrappingState(state, machine)) {
                determinedErrorStates.add(state);
            }
        }

        // identify the dummy state by finding an illegal learner transition
        for (Object state : determinedErrorStates) {
            for (TlsWord input : machine.getAlphabet()) {
                SulResponse output =
                        (SulResponse) machine.getMealyMachine().getOutput(state, input);
                if (output.isIllegalTransitionFlag()) {
                    determinedDummyState = machine.getMealyMachine().getSuccessor(state, input);
                    break;
                }
            }
            if (determinedDummyState != null) {
                break;
            }
        }

        graphDetails.setErrorStates(determinedErrorStates);
        graphDetails.setIllegalTransitionLearnerState(determinedDummyState);

        if (determinedErrorStates.isEmpty()) {
            return Arrays.asList(
                    new IgnoredInputIssue(
                            new ArrayList<>(), "Could not determine the error state. "));
        } else {
            return Arrays.asList();
        }
    }

    private boolean isTrappingState(Object state, StateMachine machine) {
        for (TlsWord input : machine.getAlphabet()) {
            // determine if state can only be left through reset or illegal learner transition
            if (input.getType() != TlsWordType.RESET_CONNECTION
                    && !((SulResponse) machine.getMealyMachine().getOutput(state, input))
                            .isIllegalTransitionFlag()
                    && machine.getMealyMachine().getSuccessor(state, input) != state) {
                return false;
            }
        }
        return true;
    }
}
