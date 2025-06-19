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
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import de.rub.nds.statevulnfinder.core.issue.UnknownMessageIssue;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import java.util.LinkedList;
import java.util.Stack;

public class UnknownMessageSubclassifier extends ResponseSubclassifier {

    @Override
    public boolean responseIndicatesVulnerability(SulResponse sulResponse, boolean onHappyFlow) {
        return (!sulResponse.isIllegalTransitionFlag()
                && sulResponse.getResponseFingerprint().getMessageList() != null
                && sulResponse.getResponseFingerprint().getMessageList().stream()
                        .anyMatch(msg -> msg instanceof UnknownMessage));
    }

    @Override
    public StateMachineIssue getVulnerability(Stack<TlsWord> wordStack) {
        return new UnknownMessageIssue(new LinkedList<>(wordStack));
    }
}
