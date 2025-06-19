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
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author robert
 */
public class NoHappyFlowIssue extends StateMachineIssue {

    private final ResponseFingerprint response;
    private List<Class> actualMessageClasses;
    private final List<TlsWord> accessSequence;

    public NoHappyFlowIssue(
            ResponseFingerprint response, String reason, List<TlsWord> accessSequence) {
        super(StateMachineIssueType.NO_HAPPY_FLOW, reason);
        this.response = response;
        this.accessSequence = accessSequence;
    }

    public List<Class> getActualMessageClasses() {
        return actualMessageClasses;
    }

    public void setActualMessageClasses(List<Class> actualMessageClasses) {
        this.actualMessageClasses = actualMessageClasses;
    }

    @Override
    public String toString() {
        return "NoHappyFlowIssue{"
                + "received="
                + appendReceived()
                + " Sent="
                + accessSequence
                + " Reason="
                + getReason()
                + '}';
    }

    private String appendReceived() {
        if (response == null
                || response.getMessageList() == null
                || response.getMessageList().isEmpty()) {
            return "NONE";
        } else {
            return response.getMessageList().stream()
                    .map(ProtocolMessage::toCompactString)
                    .collect(Collectors.joining(","));
        }
    }

    @Override
    public List<TlsWord> getPath() {
        return accessSequence;
    }
}
