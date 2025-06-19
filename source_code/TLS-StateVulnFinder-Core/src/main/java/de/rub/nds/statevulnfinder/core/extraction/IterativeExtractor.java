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
import de.rub.nds.statevulnfinder.core.extraction.alphabet.NamedListAlphabet;
import java.util.LinkedList;
import java.util.List;
import net.automatalib.words.Alphabet;
import net.automatalib.words.impl.ListAlphabet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class IterativeExtractor extends Extractor {

    private static final Logger LOG = LogManager.getLogger();

    private String stage;
    private LearnerReport learnerReport;
    private final List<NamedListAlphabet> alphabets;

    public IterativeExtractor(
            VulnerabilityFinderConfig finderConfig,
            ScanReport scanReport,
            List<NamedListAlphabet> alphabets,
            TargetSulProvider sulProvider) {
        super(finderConfig, scanReport, alphabets.get(0), sulProvider);
        this.alphabets = alphabets;
        if (alphabets.isEmpty()) {
            throw new IllegalArgumentException("List of alphabets must not be empty");
        }
    }

    @Override
    public LearnerReport extractAnalyzedStateMachine() {
        prepareWrappedSuls(buildCacheAlphabet());
        int ctr = 0;
        for (NamedListAlphabet<TlsWord> nextAlphabet : alphabets) {
            ctr++;
            stage = "alphabet-" + ctr;
            LOG.info(
                    "Starting learning with {} ({}) for {}",
                    stage,
                    nextAlphabet.getName(),
                    getFinderConfig().getImplementationName());
            setAlphabet(nextAlphabet);
            super.extractAnalyzedStateMachine();
            LOG.info(
                    "Finished learning with {} ({}) for {} ",
                    stage,
                    nextAlphabet.getName(),
                    getFinderConfig().getImplementationName());
            if (getFinderConfig().isExportResults()) {
                ResultWriter.write(
                        learnerReport
                                .getAnalysisResults()
                                .get(learnerReport.getAnalysisResults().size() - 1),
                        getFinderConfig().getImplementationName(),
                        getOutputDirectory(),
                        getFinderConfig().isWriteOnlyCrucialResults());
            }
            if (learnerReport
                            .getAnalysisResults()
                            .get(learnerReport.getAnalysisResults().size() - 1)
                            .getExtractorResult()
                            .isAbortedLearning()
                    || (getFinderConfig().getAlphabetLimit() > -1
                            && getFinderConfig().getAlphabetLimit() >= ctr)) {
                break;
            }
        }
        return learnerReport;
    }

    @Override
    protected String getOutputDirectory() {
        return super.getOutputDirectory() + "/" + stage + "/";
    }

    private Alphabet buildCacheAlphabet() {
        List<TlsWord> uniqueWords = new LinkedList<>();
        for (Alphabet alphabet : alphabets) {
            alphabet.forEach(
                    word -> {
                        if (!uniqueWords.contains((TlsWord) word)) {
                            uniqueWords.add((TlsWord) word);
                        }
                    });
        }
        return new ListAlphabet(uniqueWords);
    }

    @Override
    protected LearnerReport provideReport(ExtractorResult extractorResult) {
        AnalysisResult analyzedResult = analyzeExtractorResult(extractorResult);
        if (learnerReport == null) {
            learnerReport = new LearnerReport(getScanReport());
        }
        learnerReport.addResult(analyzedResult);
        learnerReport.setTimeout(getFinderConfig().getMinTimeout());
        return learnerReport;
    }
}
