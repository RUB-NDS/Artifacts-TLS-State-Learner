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

public class UnknownMessageIssue extends StateMachineIssue {
    private final List<TlsWord> pathToAlert;

    public UnknownMessageIssue(List<TlsWord> unknownMessageFlow) {
        super(StateMachineIssueType.UNKNOWN_MESSAGE, "Found an unknown message in response");
        this.pathToAlert = unknownMessageFlow;
    }

    @Override
    public List<TlsWord> getPath() {
        return pathToAlert;
    }

    @Override
    public String toString() {
        return "Reason: " + this.getReason() + ", Access Path: " + this.getPath();
    }
}
