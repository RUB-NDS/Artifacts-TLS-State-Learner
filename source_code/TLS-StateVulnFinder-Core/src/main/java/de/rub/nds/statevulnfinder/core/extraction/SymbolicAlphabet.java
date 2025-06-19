/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.extraction;

import de.rub.nds.statevulnfinder.core.algorithm.words.ChangeCipherSpecWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.ClientHelloWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.FinishedWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.GenericMessageWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.extraction.alphabet.NamedListAlphabet;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Defines symbols and their associated word implementations. This makes it easy for the user to
 * specify a custom input alphabet.
 */
public class SymbolicAlphabet {

    private static final Map<String, TlsWord> symbolicMap;

    static {
        symbolicMap = new LinkedHashMap<>();
        symbolicMap.put(
                "RSA_CLIENT_HELLO",
                new ClientHelloWord(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256));
        symbolicMap.put(
                "RSA_CLIENT_KEY_EXCHANGE",
                new GenericMessageWord(new RSAClientKeyExchangeMessage()));
        symbolicMap.put("HEARTBEAT", new GenericMessageWord(new HeartbeatMessage()));
        symbolicMap.put("ALERT", new GenericMessageWord(new AlertMessage()));
        symbolicMap.put("CHANGE_CIPHER_SPEC", new ChangeCipherSpecWord());
        symbolicMap.put("FINISHED", new FinishedWord());
        symbolicMap.put("APPLICATION_MESSAGE", new GenericMessageWord(new ApplicationMessage()));
        symbolicMap.put(
                "HELLO_APPLICATION_MESSAGE",
                new GenericMessageWord(buildCustomApplicationMessage("Hello")));
    }

    private static ApplicationMessage buildCustomApplicationMessage(String text) {
        ApplicationMessage am = new ApplicationMessage();
        am.setData(text.getBytes());
        return am;
    }

    public static List<String> getAvailableSymbols() {
        return new ArrayList<>(symbolicMap.keySet());
    }

    public static NamedListAlphabet createAlphabet(List<String> symbols) {
        List<String> availableSymbols = getAvailableSymbols();
        List<String> unsupportedSymbols = new ArrayList<>(symbols);
        unsupportedSymbols.removeAll(availableSymbols);
        if (!unsupportedSymbols.isEmpty()) {
            throw new UnsupportedOperationException(
                    "The following symbols are not supprted: "
                            + unsupportedSymbols
                            + "\n Supported symbols: "
                            + availableSymbols);
        }
        List<TlsWord> tlsWords = new ArrayList<>(symbols.size());
        for (String string : symbols) {
            tlsWords.add(symbolicMap.get(string));
        }
        return new NamedListAlphabet<>(tlsWords, "Custom");
    }
}
