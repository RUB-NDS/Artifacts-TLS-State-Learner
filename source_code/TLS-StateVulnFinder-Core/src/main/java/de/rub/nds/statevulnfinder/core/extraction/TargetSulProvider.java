/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.extraction;

import de.learnlib.api.SUL;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.statevulnfinder.core.algorithm.HappyFlowEQOracle;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.Analyzer;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.config.VulnerabilityFinderConfig;
import de.rub.nds.statevulnfinder.core.sul.TlsSul;
import net.automatalib.words.Alphabet;

public interface TargetSulProvider {
    public abstract TlsSul getSul(VulnerabilityFinderConfig finderConfig, ScanReport scanReport);

    public abstract HappyFlowEQOracle getHappyFlowOracle(
            Alphabet<TlsWord> alphabet,
            SUL<TlsWord, SulResponse> systemUnderTest,
            VulnerabilityFinderConfig config);

    public abstract Analyzer getAnalyzer(GraphDetails graphDetails);
}
