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
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import java.util.List;

public class LeavingHappyFlowIssue extends StateMachineIssue {
    private final List<TlsWord> noFailFastFlows;
    private final ResponseFingerprint response;

    public LeavingHappyFlowIssue(List<TlsWord> noFailFastFlows, String reason) {
        super(StateMachineIssueType.LEAVING_HAPPY_FLOW, reason);
        this.noFailFastFlows = noFailFastFlows;
        this.response = null;
    }

    public LeavingHappyFlowIssue(
            List<TlsWord> noFailFastFlows, ResponseFingerprint response, String reason) {
        super(StateMachineIssueType.LEAVING_HAPPY_FLOW, reason);
        this.noFailFastFlows = noFailFastFlows;
        this.response = response;
    }

    @Override
    public String toString() {
        return this.getReason()
                + "Invalid message flow that did not lead to error state: "
                + getPath()
                + appendReceived();
    }

    private String appendReceived() {
        if (response != null) {
            return " - Received " + response.toString();
        } else {
            return "";
        }
    }

    @Override
    public List<TlsWord> getPath() {
        return noFailFastFlows;
    }
}
