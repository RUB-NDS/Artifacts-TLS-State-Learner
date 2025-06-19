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
import de.rub.nds.statevulnfinder.core.issue.KeyblockLeakVulnerability;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import de.rub.nds.tlsattacker.core.constants.AlertByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.record.Record;
import java.util.List;
import java.util.Stack;

public class KeyblockLeakSubclassifier extends ResponseSubclassifier {

    private static final int PLAINTEXT_ALERT_RECORD_SIZE =
            RecordByteLength.CONTENT_TYPE
                    + RecordByteLength.PROTOCOL_VERSION
                    + RecordByteLength.RECORD_LENGTH
                    + AlertByteLength.LEVEL_LENGTH
                    + AlertByteLength.DESCRIPTION_LENGTH;

    @Override
    public boolean responseIndicatesVulnerability(SulResponse sulResponse, boolean onHappyFlow) {
        return containsEncryptedAlertAfterCCS(sulResponse.getResponseFingerprint().getRecordList())
                && !onHappyFlow;
    }

    @Override
    public StateMachineIssue getVulnerability(Stack<TlsWord> wordStack) {
        return new KeyblockLeakVulnerability(wordStack);
    }

    private boolean containsEncryptedAlertAfterCCS(List<Record> records) {
        boolean sawCCS = false;
        for (Record record : records) {
            if (record.getContentMessageType() == ProtocolMessageType.CHANGE_CIPHER_SPEC) {
                sawCCS = true;
            } else if (sawCCS
                    && record.getContentMessageType() == ProtocolMessageType.ALERT
                    && record.getCompleteRecordBytes().getValue().length
                            > PLAINTEXT_ALERT_RECORD_SIZE) {
                return true;
            }
        }
        return false;
    }
}
