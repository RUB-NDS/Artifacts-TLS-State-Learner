/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.extraction.alphabet;

import de.rub.nds.statevulnfinder.core.algorithm.words.PaddingOracleWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.probe.padding.vector.PaddingVector;
import de.rub.nds.tlsscanner.core.probe.padding.vector.VeryShortPaddingGenerator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class PaddingOracleWords {

    public static Map<String, TlsWord> getAll() {
        Map<String, TlsWord> wordMap = new LinkedHashMap<>();
        List<PaddingVector> paddingRecords =
                new VeryShortPaddingGenerator()
                        .getVectors(
                                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12);
        for (PaddingVector paddingVector : paddingRecords) {
            // wordList.add(new PaddingOracleWord(paddingVector.createRecord(),
            // ProtocolMessageType.ALERT));
            wordMap.put(
                    "PO_APPLICATION_" + paddingVector.getIdentifier(),
                    new PaddingOracleWord(
                            paddingVector.getIdentifier(), ProtocolMessageType.APPLICATION_DATA));
            wordMap.put(
                    "PO_CHANGE_CIPHER_SPEC_" + paddingVector.getIdentifier(),
                    new PaddingOracleWord(
                            paddingVector.getIdentifier(), ProtocolMessageType.CHANGE_CIPHER_SPEC));
            wordMap.put(
                    "PO_HANDSHAKE_" + paddingVector.getIdentifier(),
                    new PaddingOracleWord(
                            paddingVector.getIdentifier(), ProtocolMessageType.HANDSHAKE));
            wordMap.put(
                    "PO_HEARTBEAT_" + paddingVector.getIdentifier(),
                    new PaddingOracleWord(
                            paddingVector.getIdentifier(), ProtocolMessageType.HEARTBEAT));
        }
        return wordMap;
    }
}
