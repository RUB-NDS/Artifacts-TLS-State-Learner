/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2023 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.analysis.classifier.subclassifier;

import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.issue.InternalErrorIssue;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import java.util.LinkedList;
import java.util.Stack;

public class InternalErrorSubclassifier extends ResponseSubclassifier {

    @Override
    public boolean responseIndicatesVulnerability(SulResponse sulResponse, boolean onHappyFlow) {
        ResponseFingerprint fingerprint = sulResponse.getResponseFingerprint();
        for (ProtocolMessage message : fingerprint.getMessageList()) {
            if (!(message instanceof AlertMessage)) {
                return false;
            }
            AlertMessage alert = (AlertMessage) message;
            AlertDescription description =
                    AlertDescription.getAlertDescription(alert.getDescription().getValue());
            return description == AlertDescription.INTERNAL_ERROR;
        }
        return false;
    }

    @Override
    public StateMachineIssue getVulnerability(Stack<TlsWord> wordStack) {
        return new InternalErrorIssue(new LinkedList<>(wordStack), "Received internal error!");
    }
}
