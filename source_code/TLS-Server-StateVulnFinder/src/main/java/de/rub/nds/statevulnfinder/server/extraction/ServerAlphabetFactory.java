/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.server.extraction;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.statevulnfinder.core.algorithm.words.ClientHelloWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.ResetConnectionWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.ResumingClientHelloWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.extraction.AlphabetFactory;
import de.rub.nds.statevulnfinder.core.extraction.alphabet.*;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ServerAlphabetFactory extends AlphabetFactory {

    private static ServerAlphabetFactory reference;

    public static ServerAlphabetFactory getReference() {
        if (reference == null) {
            reference = new ServerAlphabetFactory();
        }
        return reference;
    }

    @Override
    protected List<TlsWord> getBleichenbacherWords(ScanReport scanReport) {
        ServerReport serverReport = (ServerReport) scanReport;
        return new LinkedList<>(BleichenbacherOracleWords.getAll(serverReport).values());
    }

    @Override
    protected List<TlsWord> getShortWords(ScanReport report, boolean includeOurHello) {
        List<TlsWord> wordList = new LinkedList<>();
        ServerReport serverReport = (ServerReport) report;
        wordList.addAll(getHappyFlowWords(report, includeOurHello));
        wordList.addAll(
                ServerWords.getShort(
                                (Set<CipherSuite>)
                                        serverReport
                                                .getSetResult(
                                                        TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES)
                                                .getSet(),
                                NamedGroup.SECP384R1)
                        .values());
        wordList.addAll(getLearnerWords(ResumingClientHelloWord.ResumptionType.ID));
        wordList.addAll(SharedWords.getShort(true).values());
        return wordList;
    }

    @Override
    protected List<TlsWord> getNormalWords(ScanReport report, boolean includeOurHello) {
        List<TlsWord> wordList = new LinkedList<>();
        ServerReport serverReport = (ServerReport) report;
        boolean includeAppData =
                serverReport.getResult(TlsAnalyzedProperty.SUPPORTS_HTTPS) != TestResults.TRUE;
        if (includeOurHello) {
            wordList.addAll(
                    ClientWords.getAll(
                                    (Set<CipherSuite>)
                                            serverReport
                                                    .getSetResult(
                                                            TlsAnalyzedProperty
                                                                    .SUPPORTED_CIPHERSUITES)
                                                    .getSet(),
                                    includeAppData)
                            .values());
        } else {
            wordList.addAll(ClientWords.getNonHelloAll(includeAppData).values());
        }
        wordList.addAll(ServerWords.getNonHelloAll().values());
        wordList.addAll(
                ServerWords.getHelloShort(
                                (Set<CipherSuite>)
                                        serverReport
                                                .getSetResult(
                                                        TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES)
                                                .getSet(),
                                NamedGroup.SECP384R1)
                        .values());
        wordList.addAll(SharedWords.getAll(includeAppData).values());
        wordList.addAll(getLearnerWords(ResumingClientHelloWord.ResumptionType.ID));
        return wordList;
    }

    protected Map<String, TlsWord> getAvailableSymbols(ScanReport report) {
        Map<String, TlsWord> wordMap = new LinkedHashMap<>();
        ServerReport serverReport = (ServerReport) report;
        boolean includeAppData =
                serverReport.getResult(TlsAnalyzedProperty.SUPPORTS_HTTPS) != TestResults.TRUE;
        wordMap.putAll(
                ClientWords.getAll(
                        (Set<CipherSuite>)
                                serverReport
                                        .getSetResult(TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES)
                                        .getSet(),
                        includeAppData));
        wordMap.putAll(
                ServerWords.getAll(
                        (Set<CipherSuite>)
                                serverReport
                                        .getSetResult(TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES)
                                        .getSet(),
                        NamedGroup.SECP384R1));
        wordMap.putAll(SharedWords.getAll(includeAppData));
        wordMap.putAll(PaddingOracleWords.getAll());
        wordMap.putAll(BleichenbacherOracleWords.getAll(serverReport));
        wordMap.put("RESET_CONNECTION", new ResetConnectionWord());
        wordMap.put(
                "TICKET_RESUMING_HELLO",
                new ResumingClientHelloWord(ResumingClientHelloWord.ResumptionType.TICKET));
        wordMap.put(
                "ID_RESUMING_HELLO",
                new ResumingClientHelloWord(ResumingClientHelloWord.ResumptionType.ID));
        wordMap.put(
                "TLS13_TICKET_RESUMING_HELLO",
                new ResumingClientHelloWord(ResumingClientHelloWord.ResumptionType.TLS_1_3_TICKET));
        return wordMap;
    }

    protected List<TlsWord> getLearnerWords(ResumingClientHelloWord.ResumptionType resumptionType) {
        List<TlsWord> learnerWords = new LinkedList<>();
        learnerWords.add(new ResetConnectionWord());
        learnerWords.add(new ResumingClientHelloWord(resumptionType));
        return learnerWords;
    }

    @Override
    protected List<TlsWord> getHappyFlowWords(ScanReport report, boolean includeOurHello) {
        List<TlsWord> wordList = new LinkedList<>();
        ServerReport serverReport = (ServerReport) report;
        boolean includeAppData =
                serverReport.getResult(TlsAnalyzedProperty.SUPPORTS_HTTPS) != TestResults.TRUE;
        if (includeOurHello) {
            wordList.addAll(
                    ClientWords.getShort(
                                    (Set<CipherSuite>)
                                            serverReport
                                                    .getSetResult(
                                                            TlsAnalyzedProperty
                                                                    .SUPPORTED_CIPHERSUITES)
                                                    .getSet(),
                                    includeAppData)
                            .values());
        } else {
            wordList.addAll(ClientWords.getNonHelloShort(!includeAppData).values());
        }
        wordList.addAll(SharedWords.getHappyFlow(includeAppData).values());
        return wordList;
    }

    @Override
    protected List<Set<TlsWord>> getHelloSets(ScanReport report) {
        ServerReport serverReport = (ServerReport) report;
        List<Set<TlsWord>> helloSets = new LinkedList<>();
        helloSets.add(
                ClientWords.getMinimumHelloSet(
                        (Set<CipherSuite>)
                                serverReport
                                        .getSetResult(TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES)
                                        .getSet()));
        helloSets.add(
                ClientWords.getBasicHelloSet(
                        (Set<CipherSuite>)
                                serverReport
                                        .getSetResult(TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES)
                                        .getSet()));
        helloSets.add(
                ClientWords.getLargeHelloSet(
                        (Set<CipherSuite>)
                                serverReport
                                        .getSetResult(TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES)
                                        .getSet()));
        return helloSets;
    }

    @Override
    protected List<NamedListAlphabet> expandAlphabets(
            List<NamedListAlphabet> intermediateAlphabets) {
        List<NamedListAlphabet> fullAlphabets = new LinkedList<>();
        fullAlphabets.addAll(intermediateAlphabets);
        // Copy all alphabets but replace resumption mechanism
        for (NamedListAlphabet alphabet : intermediateAlphabets) {
            List<TlsWord> adaptedWords = new LinkedList<>();
            alphabet.forEach(
                    word -> {
                        if (((TlsWord) word).getType().isRegularClientHello()) {
                            ClientHelloWord helloWord = (ClientHelloWord) word;
                            if (!helloWord.getSuite().isTLS13()) {
                                adaptedWords.add(new ClientHelloWord(helloWord.getSuite(), true));
                                return;
                            }
                        } else if (word instanceof ResumingClientHelloWord) {
                            ResumingClientHelloWord resumingHello = (ResumingClientHelloWord) word;
                            if (resumingHello.getResumptionType()
                                    == ResumingClientHelloWord.ResumptionType.ID) {
                                adaptedWords.add(
                                        new ResumingClientHelloWord(
                                                ResumingClientHelloWord.ResumptionType.TICKET));
                                return;
                            }
                        }
                        adaptedWords.add((TlsWord) word);
                    });
            fullAlphabets.add(new NamedListAlphabet(adaptedWords, "TICKET_" + alphabet.getName()));
        }
        return fullAlphabets;
    }
}
