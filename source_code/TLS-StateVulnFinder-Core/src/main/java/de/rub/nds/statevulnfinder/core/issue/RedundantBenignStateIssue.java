/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2023 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.issue;

import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.constants.StateMachineIssueType;
import java.util.List;

public class RedundantBenignStateIssue extends StateMachineIssue implements StateDivergenceIssue {

    private final Object sourceNode;
    private final Object firstTargetNode;
    private final Object secondTargetNode;
    private final List<TlsWord> accessSequence;
    private final TlsWord firstWord;
    private final TlsWord secondWord;

    public RedundantBenignStateIssue(
            Object sourceNode,
            Object firstTargetNode,
            Object secondTargetNode,
            String reason,
            TlsWord firstWord,
            TlsWord secondWord,
            List<TlsWord> accessSequence) {
        super(StateMachineIssueType.REDUNDANT_STATE, reason);
        this.sourceNode = sourceNode;
        this.firstTargetNode = firstTargetNode;
        this.secondTargetNode = secondTargetNode;
        this.accessSequence = accessSequence;
        this.firstWord = firstWord;
        this.secondWord = secondWord;
    }

    @Override
    public TlsWord getFirstWord() {
        return firstWord;
    }

    @Override
    public TlsWord getSecondWord() {
        return secondWord;
    }

    @Override
    public List<TlsWord> getPath() {
        return accessSequence;
    }

    @Override
    public String toString() {
        return "Redundant state found when transitioning from "
                + sourceNode.toString()
                + "("
                + firstWord.toString()
                + "->"
                + firstTargetNode.toString()
                + " vs "
                + secondWord.toString()
                + "->"
                + secondTargetNode.toString()
                + ")."
                + "There is a state in the TLS message flow that should not be a distinct from another state. "
                + getPath();
    }
}
