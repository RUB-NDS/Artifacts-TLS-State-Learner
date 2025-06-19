/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.extraction.alphabet;

import static de.rub.nds.statevulnfinder.core.extraction.alphabet.CipherSuiteUtils.getSortedCipherSuites;

import de.rub.nds.statevulnfinder.core.algorithm.words.ClientHelloWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.ClientKeyExchangeWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.GenericMessageWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.HRREnforcingClientHelloWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.HttpsRequestWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.ResumingClientHelloWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import java.util.*;

public class ClientWords {

    public static Map<String, TlsWord> getShort(
            Set<CipherSuite> cipherSuites, boolean includeAppData) {
        Map<String, TlsWord> wordMap = new LinkedHashMap<>();
        wordMap.putAll(getHelloShort(cipherSuites));
        wordMap.putAll(getNonHelloShort(!includeAppData));
        return wordMap;
    }

    public static Map<String, TlsWord> getAll(
            Set<CipherSuite> cipherSuites, boolean includeAppData) {
        Map<String, TlsWord> wordMap = new LinkedHashMap<>();
        wordMap.putAll(getHelloAll(cipherSuites));
        wordMap.putAll(getNonHelloAll(includeAppData));
        return wordMap;
    }

    public static Map<String, TlsWord> getHelloShort(Set<CipherSuite> cipherSuites) {
        Map<String, TlsWord> wordMap = new LinkedHashMap<>();
        boolean ec = false;
        boolean dh = false;
        boolean rsa = false;
        boolean tls13 = false;
        for (CipherSuite suite : getSortedCipherSuites(cipherSuites)) {
            if (suite.name().contains("ECDH") && !ec) {
                wordMap.put("ECDH_CLIENT_HELLO", new ClientHelloWord(suite));
                wordMap.put("ECDH_CLIENT_HELLO_TICKET", new ClientHelloWord(suite, true));
                ec = true;
            }
            if (suite.name().contains("_DHE") && !dh) {
                wordMap.put("DH_CLIENT_HELLO", new ClientHelloWord(suite));
                wordMap.put("DH_CLIENT_HELLO_TICKET", new ClientHelloWord(suite, true));
                dh = true;
            }
            if (suite.name().contains("TLS_RSA") && !rsa) {
                wordMap.put("RSA_CLIENT_HELLO", new ClientHelloWord(suite));
                wordMap.put("RSA_CLIENT_HELLO_TICKET", new ClientHelloWord(suite, true));
                rsa = true;
            }
            if (suite.isTLS13() && !tls13) {
                wordMap.put("TLS13_CLIENT_HELLO", new ClientHelloWord(suite));
                wordMap.put("TLS13_HRR_CLIENT_HELLO", new HRREnforcingClientHelloWord(suite));
                wordMap.put(
                        "TLS13_PSK_HELLO",
                        new ResumingClientHelloWord(
                                ResumingClientHelloWord.ResumptionType.TLS_1_3_TICKET));
                tls13 = true;
            }
        }
        return wordMap;
    }

    /**
     * Attempts to select a TLS 1.3 and pre TLS 1.3 cipher suite from the SUT's supported cipher
     * suites. For the latter, an RSA Kex cipher suite is preferred. If no such cipher suite is
     * available, any TLS 1.2 cipher suite, preferably with CBC mode, is used.
     *
     * @param cipherSuites the SUT's supported cipher suites
     * @return The Set of ClientHelloWords
     */
    public static Set<TlsWord> getMinimumHelloSet(Set<CipherSuite> cipherSuites) {
        Set<TlsWord> wordList = new LinkedHashSet<>();
        CipherSuite rsaCipher = null;
        CipherSuite tls13Cipher = null;
        CipherSuite preTls13Cipher = null;

        for (CipherSuite cipherSuite : getSortedCipherSuites(cipherSuites)) {
            if (!cipherSuite.isTLS13() && (preTls13Cipher == null || !preTls13Cipher.isCBC())) {
                preTls13Cipher = cipherSuite;
            }
            if (cipherSuite.name().contains("TLS_RSA")
                    && (rsaCipher == null || !rsaCipher.isCBC())) {
                rsaCipher = cipherSuite;
            }
            if (cipherSuite.isTLS13() && tls13Cipher == null) {
                tls13Cipher = cipherSuite;
            }
        }
        if (rsaCipher != null) {
            wordList.add(new ClientHelloWord(rsaCipher));
        } else if (preTls13Cipher != null) {
            wordList.add(new ClientHelloWord(preTls13Cipher));
        }
        if (tls13Cipher != null) {
            wordList.add(new ClientHelloWord(tls13Cipher));
            wordList.add(new HRREnforcingClientHelloWord(tls13Cipher));
        }
        return wordList;
    }

    /**
     * Attempts to extend the MinimumHelloSet with an ECDH, ECDHE, DH, and DHE cipher suite. In all
     * cases, CBC cipher suites are preferred. Since a set is used, the cipher selected in the
     * MinimumHelloSet may already satisfy one of these requirements.
     *
     * @param cipherSuites the SUT's supported cipher suites
     * @return The Set of ClientHelloWords
     */
    public static Set<TlsWord> getBasicHelloSet(Set<CipherSuite> cipherSuites) {
        Set<TlsWord> wordList = getMinimumHelloSet(cipherSuites);
        CipherSuite ecdhCipher = null;
        CipherSuite ecdheCipher = null;
        CipherSuite dhCipher = null;
        CipherSuite dheCipher = null;
        for (CipherSuite cipherSuite : getSortedCipherSuites(cipherSuites)) {
            if (cipherSuite.name().contains("TLS_ECDH_")
                    && (ecdhCipher == null || !ecdhCipher.isCBC())) {
                ecdhCipher = cipherSuite;
            }
            if (cipherSuite.name().contains("TLS_ECDHE_")
                    && (ecdheCipher == null || !ecdheCipher.isCBC())) {
                ecdheCipher = cipherSuite;
            }
            if (cipherSuite.name().contains("TLS_DH_") && (dhCipher == null || !dhCipher.isCBC())) {
                dhCipher = cipherSuite;
            }
            if (cipherSuite.name().contains("TLS_DHE_")
                    && (dheCipher == null || !dheCipher.isCBC())) {
                dheCipher = cipherSuite;
            }
        }

        if (ecdhCipher != null) {
            wordList.add(new ClientHelloWord(ecdhCipher));
        }
        if (ecdheCipher != null) {
            wordList.add(new ClientHelloWord(ecdheCipher));
        }
        if (dhCipher != null) {
            wordList.add(new ClientHelloWord(dhCipher));
        }
        if (dheCipher != null) {
            wordList.add(new ClientHelloWord(dheCipher));
        }
        return wordList;
    }

    /**
     * Attempts to extend the BasicHelloSet with an AEAD and stream cipher suite. Since a set is
     * used, the cipher suites selected in the Minimum- and BasicHelloSet may already satisfy one of
     * these requirements.
     *
     * @param cipherSuites the SUT's supported cipher suites
     * @return The Set of ClientHelloWords
     */
    public static Set<TlsWord> getLargeHelloSet(Set<CipherSuite> cipherSuites) {
        Set<TlsWord> wordList = getBasicHelloSet(cipherSuites);
        CipherSuite aeadCipher = null;
        CipherSuite streamCipher = null;
        for (CipherSuite cipherSuite : getSortedCipherSuites(cipherSuites)) {
            if (!cipherSuite.isTLS13()
                    && cipherSuite.isImplemented()
                    && AlgorithmResolver.getCipherType(cipherSuite) == CipherType.AEAD
                    && (aeadCipher == null
                            || !AlgorithmResolver.getKeyExchangeAlgorithm(aeadCipher)
                                    .isKeyExchangeRsa())) {
                aeadCipher = cipherSuite;
            }
            if (!cipherSuite.isTLS13()
                    && cipherSuite.isImplemented()
                    && AlgorithmResolver.getCipherType(cipherSuite) == CipherType.STREAM
                    && streamCipher == null) {
                streamCipher = cipherSuite;
            }
        }
        if (aeadCipher != null) {
            wordList.add(new ClientHelloWord(aeadCipher));
        }
        if (streamCipher != null) {
            wordList.add(new ClientHelloWord(streamCipher));
        }
        return wordList;
    }

    public static Map<String, TlsWord> getHelloAll(Set<CipherSuite> cipherSuites) {
        Map<String, TlsWord> wordMap = new LinkedHashMap<>();
        for (CipherSuite suite : getSortedCipherSuites(cipherSuites)) {
            wordMap.put("CLIENT_HELLO(" + suite.name() + ")", new ClientHelloWord(suite));
            if (suite.isTLS13()) {
                wordMap.put("TLS13_HRR_CLIENT_HELLO", new HRREnforcingClientHelloWord(suite));
            }
        }
        return wordMap;
    }

    public static Map<String, TlsWord> getNonHelloShort(boolean includeHttpRequest) {
        Map<String, TlsWord> wordMap = new LinkedHashMap<>();
        wordMap.put("CLIENT_KEY_EXCHANGE", new ClientKeyExchangeWord());
        if (includeHttpRequest) {
            wordMap.put("HTTPS-MESSAGE", new HttpsRequestWord());
        }
        return wordMap;
    }

    public static Map<String, TlsWord> getNonHelloAll(boolean includeAppData) {
        Map<String, TlsWord> wordMap = new LinkedHashMap<>();
        wordMap.putAll(getNonHelloShort(!includeAppData));
        wordMap.put("END_OF_EARLY_DATA", new GenericMessageWord(new EndOfEarlyDataMessage()));
        return wordMap;
    }
}
