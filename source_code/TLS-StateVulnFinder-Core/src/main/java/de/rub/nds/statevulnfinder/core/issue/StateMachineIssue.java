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

public abstract class StateMachineIssue implements Path<TlsWord> {

    private StateMachineIssueType type;

    private String reason;

    public StateMachineIssue(StateMachineIssueType type, String reason) {
        this.type = type;
        this.reason = reason;
    }

    public StateMachineIssueType getType() {
        return type;
    }

    public void setType(StateMachineIssueType type) {
        this.type = type;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }
}
