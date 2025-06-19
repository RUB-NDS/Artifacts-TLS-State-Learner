/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.extraction;

import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.config.VulnerabilityFinderConfig;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.core.constants.VulnerabilitySearchPattern;
import de.rub.nds.statevulnfinder.core.extraction.alphabet.NamedListAlphabet;
import de.rub.nds.statevulnfinder.core.extraction.alphabet.PaddingOracleWords;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * @author robert
 */
public abstract class AlphabetFactory {

    public NamedListAlphabet createAlphabet(List<String> symbols) {
        return SymbolicAlphabet.createAlphabet(symbols);
    }

    public NamedListAlphabet<TlsWord> createAlphabet(
            VulnerabilitySearchPattern searchPattern, ScanReport report, boolean includeOurHello) {
        List<TlsWord> wordList;
        switch (searchPattern) {
            case NORMAL:
                wordList = getNormalWords(report, includeOurHello);
                break;
            case BLEICHENBACHER:
                wordList = getShortWords(report, includeOurHello);
                wordList.addAll(getBleichenbacherWords(report));
                break;
            case PADDING_ORACLE:
                wordList = getShortWords(report, includeOurHello);
                wordList.addAll(getPaddingOracleWords());
                break;
            case ATTACKS:
                wordList = getShortWords(report, includeOurHello);
                wordList.addAll(getBleichenbacherWords(report));
                wordList.addAll(getPaddingOracleWords());
                break;
            case ALL:
                wordList = getNormalWords(report, includeOurHello);
                wordList.addAll(getPaddingOracleWords());
                wordList.addAll(getBleichenbacherWords(report));
                break;
            case SHORT:
                wordList = getShortWords(report, includeOurHello);
                break;
            case HAPPY_FLOW:
                wordList = getHappyFlowWords(report, includeOurHello);
                break;
            default:
                throw new UnsupportedOperationException("Unknown AlphabetType");
        }
        return new NamedListAlphabet<>(wordList, searchPattern.name());
    }

    public List<NamedListAlphabet> getIncreasingAlphabets(
            VulnerabilityFinderConfig finderConfig, ScanReport report) {
        List<NamedListAlphabet> baseAlphabets = new LinkedList<>();
        baseAlphabets.add(createAlphabet(VulnerabilitySearchPattern.HAPPY_FLOW, report, false));
        baseAlphabets.add(createAlphabet(VulnerabilitySearchPattern.SHORT, report, false));
        baseAlphabets.add(createAlphabet(VulnerabilitySearchPattern.ATTACKS, report, false));
        baseAlphabets.add(createAlphabet(VulnerabilitySearchPattern.ALL, report, false));
        List<Set<TlsWord>> helloLists = getHelloSets(report);

        List<NamedListAlphabet> intermediateAlphabets = new LinkedList<>();
        for (int i = 0; i < helloLists.size(); i++) {
            Set<TlsWord> helloSet = helloLists.get(i);
            for (NamedListAlphabet<TlsWord> alphabet : baseAlphabets) {
                List<TlsWord> mergedAlphabet = new LinkedList(new LinkedList<>(helloSet));
                alphabet.stream()
                        .filter(element -> element.getType() != TlsWordType.HEARTBEAT)
                        .forEach(mergedAlphabet::add);
                if (i == 0
                        || intermediateAlphabets
                                        .get(intermediateAlphabets.size() - baseAlphabets.size())
                                        .size()
                                < mergedAlphabet.size()) {
                    intermediateAlphabets.add(
                            new NamedListAlphabet(
                                    mergedAlphabet, "HELLO_" + i + "_" + alphabet.getName()));
                }

                // experimental: extend the last alphabet with a heartbeat message
                if (i == helloLists.size() - 1
                        && baseAlphabets.indexOf(alphabet) == baseAlphabets.size() - 1) {
                    List<TlsWord> heartBeatAlphabet = new LinkedList(new LinkedList<>(helloSet));
                    heartBeatAlphabet.addAll(
                            createAlphabet(VulnerabilitySearchPattern.ALL, report, false));
                    intermediateAlphabets.add(
                            new NamedListAlphabet(heartBeatAlphabet, "LAST_HEARTBEAT"));
                }
            }
        }
        return intermediateAlphabets;
    }

    protected abstract List<TlsWord> getBleichenbacherWords(ScanReport scanReport);

    protected List<TlsWord> getPaddingOracleWords() {
        return new LinkedList<>(PaddingOracleWords.getAll().values());
    }

    protected abstract List<TlsWord> getHappyFlowWords(ScanReport report, boolean includeOurHello);

    protected abstract List<TlsWord> getShortWords(ScanReport report, boolean includeOurHello);

    protected abstract List<TlsWord> getNormalWords(ScanReport report, boolean includeOurHello);

    protected abstract List<Set<TlsWord>> getHelloSets(ScanReport report);

    protected abstract List<NamedListAlphabet> expandAlphabets(
            List<NamedListAlphabet> intermediateAlphabets);
}
