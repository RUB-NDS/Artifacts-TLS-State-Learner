/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.server.extraction;

import de.learnlib.api.SUL;
import de.learnlib.oracle.membership.SULOracle;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.statevulnfinder.core.algorithm.HappyFlowEQOracle;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.Analyzer;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.config.VulnerabilityFinderConfig;
import de.rub.nds.statevulnfinder.core.extraction.TargetSulProvider;
import de.rub.nds.statevulnfinder.core.sul.TlsSul;
import de.rub.nds.statevulnfinder.server.algorithm.ServerHappyFlowEQOracle;
import de.rub.nds.statevulnfinder.server.analysis.ServerAnalyzer;
import de.rub.nds.statevulnfinder.server.sul.TlsServerSul;
import net.automatalib.words.Alphabet;

public class TlsServerSulProvider implements TargetSulProvider {

    @Override
    public TlsSul getSul(VulnerabilityFinderConfig finderConfig, ScanReport scanReport) {
        return new TlsServerSul(finderConfig, scanReport);
    }

    @Override
    public HappyFlowEQOracle getHappyFlowOracle(
            Alphabet<TlsWord> alphabet,
            SUL<TlsWord, SulResponse> systemUnderTest,
            VulnerabilityFinderConfig config) {
        SULOracle<TlsWord, SulResponse> sulOracle = new SULOracle<>(systemUnderTest);
        return new ServerHappyFlowEQOracle(sulOracle, alphabet);
    }

    @Override
    public Analyzer getAnalyzer(GraphDetails graphDetails) {
        return new ServerAnalyzer(graphDetails);
    }
}
