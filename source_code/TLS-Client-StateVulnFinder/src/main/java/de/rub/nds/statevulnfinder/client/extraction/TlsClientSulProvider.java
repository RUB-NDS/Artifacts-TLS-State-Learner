/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.client.extraction;

import de.learnlib.api.SUL;
import de.learnlib.oracle.membership.SULOracle;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.statevulnfinder.client.algorithm.ClientHappyFlowEQOracle;
import de.rub.nds.statevulnfinder.client.analysis.ClientAnalyzer;
import de.rub.nds.statevulnfinder.client.sul.TlsClientSul;
import de.rub.nds.statevulnfinder.core.algorithm.HappyFlowEQOracle;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.Analyzer;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.config.VulnerabilityFinderConfig;
import de.rub.nds.statevulnfinder.core.extraction.TargetSulProvider;
import de.rub.nds.statevulnfinder.core.sul.TlsSul;
import net.automatalib.words.Alphabet;

public class TlsClientSulProvider implements TargetSulProvider {

    @Override
    public TlsSul getSul(VulnerabilityFinderConfig finderConfig, ScanReport scanReport) {
        return new TlsClientSul(finderConfig, scanReport);
    }

    @Override
    public HappyFlowEQOracle getHappyFlowOracle(
            Alphabet<TlsWord> alphabet,
            SUL<TlsWord, SulResponse> systemUnderTest,
            VulnerabilityFinderConfig config) {
        SULOracle<TlsWord, SulResponse> sulOracle = new SULOracle<>(systemUnderTest);
        return new ClientHappyFlowEQOracle(sulOracle, alphabet);
    }

    @Override
    public Analyzer getAnalyzer(GraphDetails graphDetails) {
        return new ClientAnalyzer(graphDetails);
    }
}
