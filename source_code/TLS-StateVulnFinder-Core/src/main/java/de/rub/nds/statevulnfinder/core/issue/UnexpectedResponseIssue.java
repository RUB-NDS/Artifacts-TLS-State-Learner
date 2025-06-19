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
import java.util.Stack;

public class UnexpectedResponseIssue extends StateMachineIssue {

    private final Stack<TlsWord> messagePath;

    public UnexpectedResponseIssue(Stack<TlsWord> messagePath, String reason) {
        super(StateMachineIssueType.UNEXPECTED_RESPONSE, reason);
        this.messagePath = messagePath;
    }

    @Override
    public List<TlsWord> getPath() {
        return messagePath;
    }

    @Override
    public String toString() {
        return this.getReason()
                + "There is a message flow in the TLS StateMachine that does not yield the expected responses: "
                + getPath();
    }
}
