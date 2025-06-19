/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.client.extraction;

import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.extraction.AlphabetFactory;
import de.rub.nds.statevulnfinder.core.extraction.alphabet.ClientWords;
import de.rub.nds.statevulnfinder.core.extraction.alphabet.NamedListAlphabet;
import de.rub.nds.statevulnfinder.core.extraction.alphabet.ServerWords;
import de.rub.nds.statevulnfinder.core.extraction.alphabet.SharedWords;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class ClientAlphabetFactory extends AlphabetFactory {

    private static ClientAlphabetFactory reference;

    private ClientAlphabetFactory() {}

    public static ClientAlphabetFactory getReference() {
        if (reference == null) {
            reference = new ClientAlphabetFactory();
        }
        return reference;
    }

    @Override
    protected List<TlsWord> getBleichenbacherWords(ScanReport report) {
        // Bleichenbacher words make no sense in client scanning
        return new LinkedList<>();
    }

    @Override
    protected List<TlsWord> getShortWords(ScanReport report, boolean includeOurHello) {
        List<TlsWord> wordList = new LinkedList<>();
        ClientReport clientReport = (ClientReport) report;
        wordList.addAll(
                ClientWords.getShort(
                                new HashSet<>(clientReport.getClientAdvertisedCipherSuites()), true)
                        .values());
        wordList.addAll(getHappyFlowWords(report, includeOurHello));
        return wordList;
    }

    @Override
    protected List<TlsWord> getNormalWords(ScanReport report, boolean includeOurHello) {
        List<TlsWord> wordList = new LinkedList<>();
        ClientReport clientReport = (ClientReport) report;
        wordList.addAll(ClientWords.getNonHelloAll(false).values());
        wordList.addAll(
                ClientWords.getHelloShort(
                                new HashSet<>(clientReport.getClientAdvertisedCipherSuites()))
                        .values());
        wordList.addAll(
                ServerWords.getAll(
                                new HashSet<>(clientReport.getClientAdvertisedCipherSuites()),
                                getNonKeyShareGroup(clientReport))
                        .values());
        wordList.addAll(SharedWords.getAll(true).values());
        return wordList;
    }

    private NamedGroup getNonKeyShareGroup(ClientReport clientReport) {
        List<NamedGroup> keyShareGroups = clientReport.getClientAdvertisedKeyShareNamedGroupsList();
        List<NamedGroup> supportedGroups = clientReport.getClientAdvertisedNamedGroupsList();
        List<NamedGroup> availableGroups =
                supportedGroups.stream()
                        .filter(group -> (!keyShareGroups.contains(group) && group.isTls13()))
                        .collect(Collectors.toList());
        if (availableGroups.isEmpty()) {
            return null;
        } else {
            return availableGroups.get(0);
        }
    }

    @Override
    protected List<TlsWord> getHappyFlowWords(ScanReport report, boolean includeOurHello) {
        List<TlsWord> wordList = new LinkedList<>();
        ClientReport clientReport = (ClientReport) report;
        if (includeOurHello) {
            wordList.addAll(
                    ServerWords.getShort(
                                    new HashSet<>(clientReport.getClientAdvertisedCipherSuites()),
                                    NamedGroup.SECP384R1)
                            .values());
        } else {
            wordList.addAll(ServerWords.getNonHelloShort().values());
        }
        wordList.addAll(SharedWords.getShort(true).values());
        return wordList;
    }

    @Override
    protected List<Set<TlsWord>> getHelloSets(ScanReport report) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected List<NamedListAlphabet> expandAlphabets(
            List<NamedListAlphabet> intermediateAlphabets) {
        return intermediateAlphabets;
    }
}
