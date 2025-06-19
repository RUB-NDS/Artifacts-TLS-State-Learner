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

/**
 * Marks TLS alerts with the description of internal error. They can indicate entry points for
 * larger vulnerabilities.
 */
public class InternalErrorIssue extends StateMachineIssue {

    private final List<TlsWord> pathToAlert;

    public InternalErrorIssue(List<TlsWord> internalErrorFlow, String reason) {
        super(StateMachineIssueType.INTERNAL_ERROR, reason);
        this.pathToAlert = internalErrorFlow;
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
