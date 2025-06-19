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
import java.util.List;

public class CriticalMessageOutOfOrderIssue extends StateMachineIssue {

    private final List<TlsWord> path;
    private final String message;

    public CriticalMessageOutOfOrderIssue(List<TlsWord> path, String message) {
        super(
                StateMachineIssueType.CRITICAL_MESSAGE_OUT_OF_ORDER,
                "Critical message received in unexpected flow");
        this.message = message;
        this.path = path;
    }

    @Override
    public String toString() {
        return "CriticalMessageOutOfOrderIssue{" + "message='" + message + '\'' + '}';
    }

    @Override
    public List<TlsWord> getPath() {
        return path;
    }
}
