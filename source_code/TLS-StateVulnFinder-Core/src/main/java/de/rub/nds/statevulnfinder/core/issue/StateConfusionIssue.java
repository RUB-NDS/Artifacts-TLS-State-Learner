/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.issue;

import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.constants.StateMachineIssueType;
import java.util.Arrays;
import java.util.List;

public class StateConfusionIssue extends StateMachineIssue implements GuidedEquivalenceTestIssue {

    private final List<TlsWord> secondPathToState;
    private final List<TlsWord> firstPathToState;

    public StateConfusionIssue(
            List<TlsWord> fistPathToState, List<TlsWord> secondPathToState, String reason) {
        super(StateMachineIssueType.STATE_CONFUSION, reason);
        this.secondPathToState = secondPathToState;
        this.firstPathToState = fistPathToState;
    }

    @Override
    public List<TlsWord> getPath() {
        return secondPathToState;
    }

    @Override
    public String toString() {
        return this.getReason()
                + " Unexpected name applied to state. New path to state was: "
                + getPath();
    }

    @Override
    public List<List<TlsWord>> getEquivalenceTestStartPaths() {
        return Arrays.asList(secondPathToState, firstPathToState);
    }
}
