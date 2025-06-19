/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.client.algorithm;

import de.learnlib.api.oracle.MembershipOracle;
import de.rub.nds.statevulnfinder.core.algorithm.HappyFlowEQOracle;
import de.rub.nds.statevulnfinder.core.algorithm.words.ChangeCipherSpecWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.FinishedWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.GenericMessageWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.HelloRetryRequestWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.ServerHelloWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.ServerKeyExchangeWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import net.automatalib.automata.concepts.OutputAutomaton;
import net.automatalib.words.Alphabet;

public class ClientHappyFlowEQOracle<D, A extends OutputAutomaton<?, TlsWord, ?, D>>
        extends HappyFlowEQOracle<D, A> {

    private final Alphabet<TlsWord> alphabet;

    public ClientHappyFlowEQOracle(
            MembershipOracle<TlsWord, D> mqOracle, Alphabet<TlsWord> alphabet) {
        super(mqOracle, alphabet);
        this.alphabet = alphabet;
    }

    @Override
    protected List<List<TlsWord>> getHappyFlows() {
        List<ServerHelloWord> serverHellos = getServerHellos();
        List<List<TlsWord>> happyFlows = new LinkedList<>();
        serverHellos.forEach(
                serverHello -> {
                    happyFlows.add(buildHappyFlowForServerHello(serverHello));
                    if (serverHello.getSuite().isTLS13() && getHrrWord() != null) {
                        happyFlows.add(buildHrrFlow(serverHello));
                    }
                });
        return happyFlows;
    }

    private List<ServerHelloWord> getServerHellos() {
        return alphabet.stream()
                .filter(input -> input.getType().isRegularServerHello())
                .map(ServerHelloWord.class::cast)
                .collect(Collectors.toList());
    }

    private List<TlsWord> buildHappyFlowForServerHello(ServerHelloWord serverHello) {
        List<TlsWord> happyFlowPath = new LinkedList<>();
        happyFlowPath.add(serverHello);
        if (serverHello.getSuite().isTLS13()) {
            appendTls13Flow(happyFlowPath);
        } else {
            appendPreTls13Flow(happyFlowPath, serverHello);
        }
        return happyFlowPath;
    }

    private List<TlsWord> buildHrrFlow(ServerHelloWord serverHello) {
        List<TlsWord> happyFlowPath = new LinkedList<>();
        happyFlowPath.add(getHrrWord());
        happyFlowPath.addAll(buildHappyFlowForServerHello(serverHello));
        return happyFlowPath;
    }

    /**
     * Uses the listed HRR Word as we must specify a group.
     *
     * @return The listed HelloRetryRequest
     */
    private HelloRetryRequestWord getHrrWord() {
        for (TlsWord givenInput : alphabet) {
            if (givenInput.getType() == TlsWordType.HELLO_RETRY_REQUEST) {
                return (HelloRetryRequestWord) givenInput;
            }
        }
        return null;
    }

    private void appendTls13Flow(List<TlsWord> happyFlowPath) {
        happyFlowPath.add(new ChangeCipherSpecWord());
        happyFlowPath.add(new GenericMessageWord(new EncryptedExtensionsMessage()));
        happyFlowPath.add(new GenericMessageWord(new CertificateMessage()));
        happyFlowPath.add(new GenericMessageWord(new CertificateVerifyMessage()));
        happyFlowPath.add(new FinishedWord());
    }

    private void appendPreTls13Flow(List<TlsWord> happyFlowPath, ServerHelloWord serverHello) {
        happyFlowPath.add(new GenericMessageWord(new CertificateMessage()));
        if (serverHello.getSuite().isEphemeral()) {
            happyFlowPath.add(new ServerKeyExchangeWord());
        }
        happyFlowPath.add(new GenericMessageWord(new ServerHelloDoneMessage()));
        happyFlowPath.add(new ChangeCipherSpecWord());
        happyFlowPath.add(new FinishedWord());
        List<TlsWord> initialPath = new LinkedList<>(happyFlowPath);
        happyFlowPath.add(new GenericMessageWord(new HelloRequestMessage()));
        happyFlowPath.addAll(initialPath);
    }
}
