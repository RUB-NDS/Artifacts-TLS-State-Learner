/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.server.algorithm;

import de.learnlib.api.oracle.MembershipOracle;
import de.rub.nds.statevulnfinder.core.algorithm.HappyFlowEQOracle;
import de.rub.nds.statevulnfinder.core.algorithm.words.ChangeCipherSpecWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.ClientHelloWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.ClientKeyExchangeWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.FinishedWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.GenericMessageWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.HttpsRequestWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.PaddingOracleWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.ResetConnectionWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.ResumingClientHelloWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.ResumingClientHelloWord.ResumptionType;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import java.util.LinkedList;
import java.util.List;
import net.automatalib.automata.concepts.OutputAutomaton;
import net.automatalib.words.Alphabet;

public class ServerHappyFlowEQOracle<D, A extends OutputAutomaton<?, TlsWord, ?, D>>
        extends HappyFlowEQOracle<D, A> {

    public ServerHappyFlowEQOracle(
            MembershipOracle<TlsWord, D> mqOracle, Alphabet<TlsWord> alphabet) {
        super(mqOracle, alphabet);
    }

    @Override
    protected List<List<TlsWord>> getHappyFlows() {
        List<List<TlsWord>> happyFlows = new LinkedList<>();
        List<TlsWord> rsaHappyFlow = new LinkedList<>();
        List<TlsWord> dhHappyFlow = new LinkedList<>();
        List<TlsWord> ecdhHappyFlow = new LinkedList<>();
        List<TlsWord> tls13HappyFlow = new LinkedList<>();
        happyFlows.add(rsaHappyFlow);
        happyFlows.add(dhHappyFlow);
        happyFlows.add(ecdhHappyFlow);
        happyFlows.add(tls13HappyFlow);
        ClientHelloWord rsaHelloWord = null;
        ClientHelloWord dhHelloWord = null;
        ClientHelloWord ecdhHelloWord = null;
        ClientHelloWord tls13HelloWord = null;

        for (TlsWord word : getAlphabet()) {
            if (word instanceof ClientHelloWord
                    && ((ClientHelloWord) word).getSuite().name().contains("TLS_RSA")) {
                rsaHelloWord = (ClientHelloWord) word;
                continue;
            }
            if (word instanceof ClientHelloWord
                    && ((ClientHelloWord) word).getSuite().name().contains("TLS_DH")) {
                dhHelloWord = (ClientHelloWord) word;
                continue;
            }
            if (word instanceof ClientHelloWord
                    && ((ClientHelloWord) word).getSuite().name().contains("TLS_ECDH")) {
                ecdhHelloWord = (ClientHelloWord) word;
            }
            if (word instanceof ClientHelloWord && ((ClientHelloWord) word).getSuite().isTLS13()) {
                tls13HelloWord = (ClientHelloWord) word;
            }
        }

        // fill happyFlows, add renegotiation
        for (int i = 0; i < 2; i++) {
            if (rsaHelloWord != null) {
                rsaHappyFlow.addAll(
                        getHappyFlow(
                                rsaHelloWord.getSuite(),
                                rsaHelloWord.isIncludeSessionTicketExtension()));
            }
            if (dhHelloWord != null) {
                dhHappyFlow.addAll(
                        getHappyFlow(
                                dhHelloWord.getSuite(),
                                dhHelloWord.isIncludeSessionTicketExtension()));
            }
            if (ecdhHelloWord != null) {
                ecdhHappyFlow.addAll(
                        getHappyFlow(
                                ecdhHelloWord.getSuite(),
                                ecdhHelloWord.isIncludeSessionTicketExtension()));
            }
        }
        // only once for TLS 1.3 as there is no renegotiation
        if (tls13HelloWord != null) {
            tls13HappyFlow.add(new ClientHelloWord(tls13HelloWord.getSuite()));
            tls13HappyFlow.add(new FinishedWord());
            appendAppDataToHappyFlow(tls13HappyFlow);
            if (getAlphabet().containsSymbol(new ResetConnectionWord())
                    && getAlphabet()
                            .containsSymbol(
                                    new ResumingClientHelloWord(ResumptionType.TLS_1_3_TICKET))) {
                tls13HappyFlow.add(new ResetConnectionWord());
                tls13HappyFlow.add(
                        new ResumingClientHelloWord(
                                ResumingClientHelloWord.ResumptionType.TLS_1_3_TICKET));
            }
        }

        // append resumption happy flows
        if (getAlphabet()
                .containsSymbol(
                        new ResumingClientHelloWord(ResumingClientHelloWord.ResumptionType.ID))) {
            if (rsaHelloWord != null) {
                happyFlows.add(
                        getFullResumptionHappyFlow(
                                rsaHelloWord.getSuite(),
                                ResumingClientHelloWord.ResumptionType.ID));
            }
            if (dhHelloWord != null) {
                happyFlows.add(
                        getFullResumptionHappyFlow(
                                dhHelloWord.getSuite(), ResumingClientHelloWord.ResumptionType.ID));
            }
            if (ecdhHelloWord != null) {
                happyFlows.add(
                        getFullResumptionHappyFlow(
                                ecdhHelloWord.getSuite(),
                                ResumingClientHelloWord.ResumptionType.ID));
            }
        }

        if (getAlphabet()
                .containsSymbol(
                        new ResumingClientHelloWord(
                                ResumingClientHelloWord.ResumptionType.TICKET))) {
            if (rsaHelloWord != null) {
                happyFlows.add(
                        getFullResumptionHappyFlow(
                                rsaHelloWord.getSuite(),
                                ResumingClientHelloWord.ResumptionType.TICKET));
            }
            if (dhHelloWord != null) {
                happyFlows.add(
                        getFullResumptionHappyFlow(
                                dhHelloWord.getSuite(),
                                ResumingClientHelloWord.ResumptionType.TICKET));
            }
            if (ecdhHelloWord != null) {
                happyFlows.add(
                        getFullResumptionHappyFlow(
                                ecdhHelloWord.getSuite(),
                                ResumingClientHelloWord.ResumptionType.TICKET));
            }
        }

        return happyFlows;
    }

    private List<TlsWord> getHappyFlow(CipherSuite cipherSuite, boolean addTicketExtension) {
        List<TlsWord> happyFlow = new LinkedList<>();
        happyFlow.add(new ClientHelloWord(cipherSuite, addTicketExtension));
        happyFlow.add(new ClientKeyExchangeWord());
        happyFlow.add(new ChangeCipherSpecWord());
        happyFlow.add(new FinishedWord());
        appendAppDataToHappyFlow(happyFlow);
        return happyFlow;
    }

    private List<TlsWord> getFullResumptionHappyFlow(
            CipherSuite cipherSuite, ResumingClientHelloWord.ResumptionType resumptionType) {
        List<TlsWord> happyFlow =
                getHappyFlow(
                        cipherSuite,
                        resumptionType == ResumingClientHelloWord.ResumptionType.TICKET);
        happyFlow.add(new ResetConnectionWord());
        happyFlow.add(new ResumingClientHelloWord(resumptionType));
        happyFlow.add(new ChangeCipherSpecWord());
        happyFlow.add(new FinishedWord());
        return happyFlow;
    }

    @Override
    protected List<List<TlsWord>> getSanityFlows() {
        return getPaddingOracleSanityFlows();
    }

    private List<List<TlsWord>> getPaddingOracleSanityFlows() {
        List<List<TlsWord>> flowList = new LinkedList<>();
        // there must be a difference between AEAD and CBC due to our cache
        // and TlsSul filtering (IllegalLearnerTransition)
        ClientHelloWord aeadHello = getCipherTypeHelloWord(CipherType.AEAD, ProtocolVersion.TLS12);
        ClientHelloWord cbcHello = getCipherTypeHelloWord(CipherType.BLOCK, ProtocolVersion.TLS12);

        PaddingOracleWord paddingOracleWord =
                (PaddingOracleWord)
                        getAlphabet().stream()
                                .filter(tlsWord -> tlsWord.getType() == TlsWordType.PADDING_ORACLE)
                                .findAny()
                                .orElse(null);
        if (aeadHello != null && cbcHello != null && paddingOracleWord != null) {
            List<TlsWord> aeadFlow =
                    getHappyFlow(aeadHello.getSuite(), aeadHello.isIncludeSessionTicketExtension());
            List<TlsWord> cbcFlow =
                    getHappyFlow(cbcHello.getSuite(), cbcHello.isIncludeSessionTicketExtension());
            aeadFlow.add(paddingOracleWord);
            cbcFlow.add(paddingOracleWord);

            List<TlsWord> shortAeadFlow = new LinkedList<>(aeadFlow);
            List<TlsWord> shortCbcFlow = new LinkedList<>(cbcFlow);
            // leave out FIN
            shortAeadFlow.remove(shortAeadFlow.size() - 2);
            shortCbcFlow.remove(shortCbcFlow.size() - 2);

            flowList.add(aeadFlow);
            flowList.add(cbcFlow);
            flowList.add(shortAeadFlow);
            flowList.add(shortCbcFlow);
        }

        return flowList;
    }

    private ClientHelloWord getCipherTypeHelloWord(CipherType type, ProtocolVersion version) {
        return getAlphabet().stream()
                .filter(tlsWord -> (tlsWord.getType().isRegularClientHello()))
                .map(tlsWord -> (ClientHelloWord) tlsWord)
                .filter(
                        helloWord ->
                                helloWord.getSuite().isSupportedInProtocol(version)
                                        && AlgorithmResolver.getCipherType(helloWord.getSuite())
                                                == type)
                .findAny()
                .orElse(null);
    }

    private void appendAppDataToHappyFlow(List<TlsWord> completedHandshakeFlow) {
        HttpsRequestWord httpsRequestWord = new HttpsRequestWord();
        GenericMessageWord appDataWord = new GenericMessageWord(new ApplicationMessage());
        if (getAlphabet().containsSymbol(appDataWord)) {
            completedHandshakeFlow.add(appDataWord);
        } else if (getAlphabet().containsSymbol(httpsRequestWord)) {
            completedHandshakeFlow.add(httpsRequestWord);
        }
    }
}
