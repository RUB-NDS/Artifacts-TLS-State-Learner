/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.extraction.alphabet;

import static de.rub.nds.statevulnfinder.core.extraction.alphabet.CipherSuiteUtils.getSortedCipherSuites;

import de.rub.nds.statevulnfinder.core.algorithm.words.GenericMessageWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.HelloRetryRequestWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.ServerHelloWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.ServerKeyExchangeWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import java.util.*;

public class ServerWords {

    public static Map<String, TlsWord> getShort(
            Set<CipherSuite> cipherSuites, NamedGroup nonKeyShareGroup) {
        Map<String, TlsWord> wordMap = new LinkedHashMap<>();
        wordMap.putAll(getHelloShort(cipherSuites, nonKeyShareGroup));
        wordMap.putAll(getNonHelloShort());
        return wordMap;
    }

    public static Map<String, TlsWord> getHelloShort(
            Set<CipherSuite> cipherSuites, NamedGroup nonKeyShareGroup) {
        Map<String, TlsWord> wordMap = new LinkedHashMap<>();
        boolean ec = false;
        boolean dh = false;
        boolean rsa = false;
        boolean tls13 = false;
        for (CipherSuite suite : getSortedCipherSuites(cipherSuites)) {
            if (suite.name().contains("EC") && !ec) {
                wordMap.put("ECDH_SERVER_HELLO", new ServerHelloWord(suite));
                ec = true;
            }
            if (suite.name().contains("_DHE") && !dh) {
                wordMap.put("DH_SERVER_HELLO", new ServerHelloWord(suite));
                dh = true;
            }
            if (suite.name().contains("TLS_RSA") && !rsa) {
                wordMap.put("RSA_SERVER_HELLO", new ServerHelloWord(suite));
                rsa = true;
            }
            if (suite.isTLS13() && !tls13) {
                wordMap.put("TLS13_SERVER_HELLO", new ServerHelloWord(suite));
                if (nonKeyShareGroup != null) {
                    wordMap.put(
                            "HELLO_RETRY_REQUEST",
                            new HelloRetryRequestWord(nonKeyShareGroup, suite));
                }
                tls13 = true;
            }
        }
        return wordMap;
    }

    public static Map<String, TlsWord> getHelloAll(
            Set<CipherSuite> cipherSuites, NamedGroup nonKeyShareGroup) {
        Map<String, TlsWord> wordMap = new LinkedHashMap<>();

        for (CipherSuite suite : getSortedCipherSuites(cipherSuites)) {
            wordMap.put("SERVER_HELLO(" + suite.name() + ")", new ServerHelloWord(suite));
            if (suite.isTLS13() && nonKeyShareGroup != null) {
                wordMap.put(
                        "HELLO_RETRY_REQUEST", new HelloRetryRequestWord(nonKeyShareGroup, suite));
            }
        }
        return wordMap;
    }

    public static Map<String, TlsWord> getNonHelloShort() {
        Map<String, TlsWord> wordMap = new LinkedHashMap<>();
        wordMap.put("SERVER_KEY_EXCHANGE", new ServerKeyExchangeWord());
        wordMap.put(
                "ENCRYPTED_EXTENSIONS", new GenericMessageWord(new EncryptedExtensionsMessage()));
        wordMap.put("NEW_SESSION_TICKET", new GenericMessageWord(new NewSessionTicketMessage()));
        wordMap.put("SERVER_HELLO_DONE", new GenericMessageWord(new ServerHelloDoneMessage()));
        wordMap.put("CERTIFICATE_VERIFY", new GenericMessageWord(new CertificateVerifyMessage()));
        wordMap.put("HELLO_REQUEST", new GenericMessageWord(new HelloRequestMessage()));
        return wordMap;
    }

    public static Map<String, TlsWord> getNonHelloAll() {
        Map<String, TlsWord> wordMap = new LinkedHashMap<>();
        wordMap.putAll(getNonHelloShort());
        wordMap.put("CERTIFICATE_REQUEST", new GenericMessageWord(new CertificateRequestMessage()));
        wordMap.put("CERTIFICATE_STATUS", new GenericMessageWord(new CertificateStatusMessage()));
        // DTLS message
        wordMap.put(
                "HELLO_VERIFY_REQUEST_MESSAGE",
                new GenericMessageWord(new HelloVerifyRequestMessage()));
        return wordMap;
    }

    public static Map<String, TlsWord> getAll(
            Set<CipherSuite> cipherSuites, NamedGroup nonKeyShareGroup) {
        Map<String, TlsWord> wordMap = new LinkedHashMap<>();
        wordMap.putAll(getHelloAll(cipherSuites, nonKeyShareGroup));
        wordMap.putAll(getNonHelloAll());
        return wordMap;
    }
}
