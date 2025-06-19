/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.extraction.alphabet;

import de.rub.nds.statevulnfinder.core.algorithm.words.ChangeCipherSpecWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.DummyChangeCipherSpecWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.FinishedWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.GenericMessageWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.KeyUpdateMessage;
import java.util.LinkedHashMap;
import java.util.Map;

public class SharedWords {

    public static Map<String, TlsWord> getHappyFlow(boolean includeAppData) {
        Map<String, TlsWord> wordMap = new LinkedHashMap<>();
        AlertMessage closeNotify = new AlertMessage();
        closeNotify.setConfig(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
        wordMap.put("ALERT", new GenericMessageWord(closeNotify));
        wordMap.put("CERTIFICATE", new GenericMessageWord(new CertificateMessage()));
        wordMap.put("CHANGE_CIPHER_SPEC", new ChangeCipherSpecWord());
        wordMap.put("FINISHED", new FinishedWord());
        return wordMap;
    }

    public static Map<String, TlsWord> getShort(boolean includeAppData) {
        Map<String, TlsWord> wordMap = new LinkedHashMap<>();
        wordMap.putAll(getHappyFlow(includeAppData));
        wordMap.put("DUMMY_CHANGE_CIPHER_SPEC", new DummyChangeCipherSpecWord());
        wordMap.put("KEY_UPDATE", new GenericMessageWord(new KeyUpdateMessage()));
        wordMap.put("HEARTBEAT", new GenericMessageWord(new HeartbeatMessage()));
        return wordMap;
    }

    public static Map<String, TlsWord> getAll(boolean includeAppData) {
        Map<String, TlsWord> wordMap = new LinkedHashMap<>();
        wordMap.putAll(getShort(includeAppData));
        // wordList.add(new GenericMessageWord(new SupplementalDataMessage()));
        return wordMap;
    }
}
