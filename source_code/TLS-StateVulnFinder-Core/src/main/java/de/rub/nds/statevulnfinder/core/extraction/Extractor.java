/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.extraction;

import de.learnlib.api.SUL;
import de.learnlib.api.algorithm.LearningAlgorithm;
import de.learnlib.api.oracle.EquivalenceOracle;
import de.learnlib.api.query.DefaultQuery;
import de.learnlib.filter.statistic.sul.ResetCounterSUL;
import de.learnlib.oracle.equivalence.EQOracleChain;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.algorithm.*;
import de.rub.nds.statevulnfinder.core.algorithm.exception.LimitExceededException;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.Analyzer;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.config.VulnerabilityFinderConfig;
import de.rub.nds.statevulnfinder.core.constants.EquivalenceTestAlgorithmName;
import de.rub.nds.statevulnfinder.core.extraction.alphabet.NamedListAlphabet;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import de.rub.nds.statevulnfinder.core.sul.HintCounterSUL;
import de.rub.nds.statevulnfinder.core.sul.HintedResetCounterSUL;
import de.rub.nds.statevulnfinder.core.sul.HintedSUL;
import de.rub.nds.statevulnfinder.core.sul.TimeMeasureSUL;
import de.rub.nds.statevulnfinder.core.sul.TlsSul;
import java.io.File;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import net.automatalib.automata.transducers.MealyMachine;
import net.automatalib.incremental.ConflictException;
import net.automatalib.words.Alphabet;
import net.automatalib.words.Word;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Extractor {
    private static final Logger LOG = LogManager.getLogger(Extractor.class.getName());
    private final VulnerabilityFinderConfig finderConfig;
    private NamedListAlphabet alphabet;
    private final ScanReport scanReport;
    private final TargetSulProvider sulProvider;

    private TlsSul tlsSystemUnderTest;
    private TimeMeasureSUL timeMeasureSUL;
    private HintedSUL<TlsWord, SulResponse> wrappedSUL;
    private HintedResetCounterSUL<TlsWord, SulResponse> postCacheResetCounterSul;
    private ResetCounterSUL<TlsWord, SulResponse> preCacheResetCounterSul;
    private HintCounterSUL<TlsWord, SulResponse> hintCounterSul;
    private FastMealySULCache cachingSul;
    private TimeoutHandler timeoutHandler;
    private StatisticsRecord lastFullStats;

    private EquivalenceOracle configuredEquivalenceApproach;
    private EquivalenceOracle equivalenceOracleChain;

    private int rounds;
    private int cacheConflicts;

    long timeStamp;

    public Extractor(
            VulnerabilityFinderConfig finderConfig,
            ScanReport scanReport,
            NamedListAlphabet<TlsWord> alphabet,
            TargetSulProvider sulProvider) {
        this.finderConfig = finderConfig;
        this.alphabet = alphabet;
        this.scanReport = scanReport;
        this.sulProvider = sulProvider;
    }

    public void prepareWrappedSuls() {
        prepareWrappedSuls(alphabet);
    }

    public void prepareWrappedSuls(Alphabet<TlsWord> alphabet) {
        // setting up our TLS SUL/T (System Under Learning/Test)
        tlsSystemUnderTest = getSulProvider().getSul(getFinderConfig(), getScanReport());
        timeoutHandler = new TimeoutHandler(getFinderConfig());
        // set up timing measurements
        timeMeasureSUL = new TimeMeasureSUL(tlsSystemUnderTest);
        wrappedSUL = timeMeasureSUL;
        // wrap TLS SUL/T in SULs which analyze statistics
        hintCounterSul = new HintCounterSUL<>("hint counter", wrappedSUL);
        postCacheResetCounterSul =
                new HintedResetCounterSUL<>("post cache reset counter", hintCounterSul);
        // wrap TLS SUL/T in a cache
        cachingSul =
                new FastMealySULCache(
                        postCacheResetCounterSul,
                        alphabet,
                        new ReentrantReadWriteLock(),
                        !finderConfig.isSlowCache(),
                        timeoutHandler,
                        getFinderConfig());
        preCacheResetCounterSul =
                new ResetCounterSUL<TlsWord, SulResponse>("pre cache reset counter", cachingSul);
        timeStamp = System.currentTimeMillis();
    }

    public LearnerReport extractAnalyzedStateMachine() {
        ExtractorResult extractorResult = new ExtractorResult();
        if (tlsSystemUnderTest == null) {
            prepareWrappedSuls();
        }
        if (equivalenceOracleChain == null) {
            equivalenceOracleChain = getEQOracleChain(preCacheResetCounterSul);
        }

        boolean restartLearning;
        rounds = 0;

        // loop allows us to restart the learning algorithm while reusing our cache
        try {
            do {
                restartLearning = false;
                try {
                    provideResult(preCacheResetCounterSul, timeStamp, extractorResult);
                } catch (TLSConflictException e) {
                    cacheConflicts++;
                    LOG.warn(
                            "Detected cache conflict for SUL {}. Input:"
                                    + e.getInput()
                                    + "\nCached Prefix Output: "
                                    + e.getExpectedOutput()
                                    + "\nConflicting Output:  "
                                    + e.getNewOutput()
                                    + ". Restarting SUL/T with new cache.",
                            getFinderConfig().getImplementationName());
                    Word<SulResponse> majorityResult =
                            tlsSystemUnderTest.majorityVote(
                                    e.getInput(), getFinderConfig().getMajorityVote());
                    // Majority votes bypass the cache and hence all of its filter mechanisms.
                    // Sometimes we would thus store responses that should have been filtered out.
                    // Running the filters here ensures that we do not store these responses.
                    FastMealySULCacheStateTracker cacheStateTracker =
                            new FastMealySULCacheStateTracker();
                    cachingSul.overwrite(
                            e.getInput(),
                            cacheStateTracker.applyCacheFiltersToInputOutputPair(
                                    e.getInput(), majorityResult));
                    restartLearning = true;
                    // log all resets
                }
            } while (restartLearning);
        } catch (LimitExceededException exception) {
            processLimitException(exception, extractorResult);
            finalizeResult(timeStamp, extractorResult);
        }
        return provideReport(extractorResult);
    }

    private void processLimitException(
            LimitExceededException exception, ExtractorResult extractorResult) {
        LOG.info(
                "Limit {} Exceeded for {} - Aborted Learning with alphabet {}",
                exception.getType().name(),
                getFinderConfig().getImplementationName(),
                alphabet.getName());
        extractorResult.setProbablyBlacklisted(exception.stopImmediately());
        extractorResult.setIncomplete(true);
    }

    private void provideResult(
            SUL<TlsWord, SulResponse> preCacheResetCounterSul,
            long startTime,
            ExtractorResult extractorResult)
            throws ConflictException {
        tlsSystemUnderTest.setConfirmingVulnerabilities(false);

        // create our learning algorithm
        LearningAlgorithm<MealyMachine, List<TlsWord>, SulResponse> algorithm =
                LearningAlgorithmFactory.getAlgorithm(
                        getFinderConfig().getLearningAlgorithm(),
                        alphabet,
                        preCacheResetCounterSul);

        // running learning and collecting important statistics
        MealyMachine hypothesis;
        DefaultQuery<List<TlsWord>, SulResponse> counterExample;
        algorithm.startLearning();
        // while our equivalence oracles provide counter examples we keep refining the hypothesis
        do {
            hypothesis = algorithm.getHypothesisModel();
            if (rounds == 0) {
                // keep results from before reset until a new hypothesis is found
                extractorResult.reset();
                clearOutputDirectory();
            }
            StateMachine stateMachine = new StateMachine(hypothesis, alphabet, getFinderConfig());
            extractorResult.addHypothesis(stateMachine);
            // it is useful to print intermediate hypothesis as learning is running
            if (getFinderConfig().getExportHypotheses()) {
                ResultWriter.writeHypothesis(
                        stateMachine, "hyp" + (rounds + 1) + ".dot", getOutputDirectory());
            }
            LOG.info(
                    "Received hypothesis with {} states. Applying equivalence oracle to validate.",
                    hypothesis.size());
            counterExample = equivalenceOracleChain.findCounterExample(hypothesis, alphabet);
            if (counterExample != null) {
                LOG.info(
                        "Equivalence oracle found a counter example. Instructing learner to refine hypothesis.");
                algorithm.refineHypothesis(counterExample);
            }
            rounds++;
        } while (counterExample != null);
        LOG.info("No counter example found. Accepting hypothesis.");
        finalizeResult(startTime, extractorResult);
        printStatsToConsole(extractorResult);
    }

    public void printStatsToConsole(ExtractorResult extractorResult) {
        LOG.info("Finished Learning");
        LOG.info(
                "\nStats (current alphabet)\n--------------------------------\n{}\n",
                extractorResult.getStatistics().toReadable(true));
        LOG.info(
                "\nStats (total)\n--------------------------------\n{}\n",
                lastFullStats.toReadable(false));
    }

    public EquivalenceOracle getEQOracleChain(SUL<TlsWord, SulResponse> wrappingSul) {
        // create first equivalence oracle that provides counter examples to the learning algorithm
        configuredEquivalenceApproach =
                EquivalenceAlgorithmFactory.getAlgorithm(
                        getFinderConfig().getEquivalenceAlgorithm(),
                        alphabet,
                        wrappingSul,
                        getFinderConfig());
        /*
         * create second equivalence oracle that provides counter examples to the learning algorithm based on found
         * vulnerabilities in the state machine/hypothesis found by the learning algorithm
         */
        EquivalenceOracle analyzerAlgorithm =
                EquivalenceAlgorithmFactory.getAlgorithm(
                        EquivalenceTestAlgorithmName.VULNERABILITY,
                        alphabet,
                        wrappingSul,
                        getFinderConfig());
        /*
         * Create third equivalence oracle that returns a hardcoded tls handshake
         */
        EquivalenceOracle happyFlowAlgorithm =
                getSulProvider().getHappyFlowOracle(alphabet, wrappingSul, getFinderConfig());
        // chain all together in the correct order
        LinkedList<EquivalenceOracle> equivalenceOracles = new LinkedList<>();
        equivalenceOracles.add(happyFlowAlgorithm);
        equivalenceOracles.add(configuredEquivalenceApproach);
        equivalenceOracles.add(analyzerAlgorithm);
        return new EQOracleChain(equivalenceOracles);
    }

    private void finalizeResult(long startTime, ExtractorResult extractorResult) {
        if (extractorResult.isAbortedLearning()) {
            extractorResult.filterBrokenHypotheses();
        }
        StateMachine stateMachine = extractorResult.getLastHypothesis();
        int states =
                (stateMachine != null && stateMachine.getMealyMachine() != null)
                        ? stateMachine.getMealyMachine().size()
                        : 0;
        extractorResult.setLearnedModel(stateMachine);

        if (lastFullStats == null) {
            lastFullStats = new StatisticsRecord();
        }
        StatisticsRecord fullStats =
                new StatisticsRecord(
                        preCacheResetCounterSul.getStatisticalData().getCount(),
                        postCacheResetCounterSul.getStatisticalData().getCount(),
                        hintCounterSul.getCounter().getCount(),
                        hintCounterSul.getStepsCounter().getCount(),
                        System.currentTimeMillis() - startTime,
                        states,
                        extractorResult.getHypotheses().size(),
                        cacheConflicts);
        extractorResult.setStatistics(new StatisticsRecord(lastFullStats, fullStats));
        lastFullStats = fullStats;
    }

    protected AnalysisResult analyzeExtractorResult(ExtractorResult extractorResult) {
        GraphDetails graphDetails = new GraphDetails();
        Analyzer analyzer = sulProvider.getAnalyzer(graphDetails);
        List<StateMachineIssue> assumedVulnerabilities = new LinkedList<>();
        List<StateMachineIssue> confirmedVulnerabilities = new LinkedList<>();

        if (extractorResult.getLearnedModel() != null
                && extractorResult.getLearnedModel().getMealyMachine() != null) {
            assumedVulnerabilities =
                    analyzer.findVulnerabilities(extractorResult.getLearnedModel());
            if (extractorResult.isAbortedLearning() && !extractorResult.isProbablyBlacklisted()) {
                confirmedVulnerabilities =
                        limitReachedVulnerabilityConfirmation(
                                assumedVulnerabilities, extractorResult);
            } else if (!extractorResult.isAbortedLearning()) {
                confirmedVulnerabilities = assumedVulnerabilities;
            }
        }
        return new AnalysisResult(
                graphDetails,
                assumedVulnerabilities,
                confirmedVulnerabilities,
                extractorResult,
                alphabet.getName());
    }

    /**
     * Performs connections beyond the connection limit to confirm assumed vulnerabilites.
     *
     * @param assumedVulnerabilities The list of vulnerabilites determined by our analysis
     * @param extractorResult The state machine obtained thus far
     * @return The list of confirmed vulnerabilities
     */
    private List<StateMachineIssue> limitReachedVulnerabilityConfirmation(
            List<StateMachineIssue> assumedVulnerabilities, ExtractorResult extractorResult) {
        List<StateMachineIssue> confirmedVulnerabilities;
        tlsSystemUnderTest.setConfirmingVulnerabilities(true);
        AnalyzerEQOracle analyzerAlgorithm =
                (AnalyzerEQOracle)
                        EquivalenceAlgorithmFactory.getAlgorithm(
                                EquivalenceTestAlgorithmName.VULNERABILITY,
                                alphabet,
                                preCacheResetCounterSul,
                                getFinderConfig());
        confirmedVulnerabilities =
                analyzerAlgorithm.confirmVulnerabilities(
                        assumedVulnerabilities,
                        extractorResult.getLearnedModel().getMealyMachine());
        return confirmedVulnerabilities;
    }

    private void clearOutputDirectory() {
        File folder = new File(getOutputDirectory());
        folder.mkdirs();
        for (File file : folder.listFiles()) {
            if (!file.isDirectory()) {
                file.delete();
            }
        }
    }

    protected String getOutputDirectory() {
        return getFinderConfig().getOutput();
    }

    protected LearnerReport provideReport(ExtractorResult extractorResult) {
        AnalysisResult analyzedResult = analyzeExtractorResult(extractorResult);
        if (getFinderConfig().isExportResults()) {
            ResultWriter.write(
                    analyzedResult,
                    getFinderConfig().getImplementationName(),
                    getOutputDirectory(),
                    getFinderConfig().isWriteOnlyCrucialResults());
        }
        LearnerReport learnerReport = new LearnerReport(getScanReport());
        learnerReport.addResult(analyzedResult);
        learnerReport.setTimeout(getFinderConfig().getMinTimeout());
        return learnerReport;
    }

    public ScanReport getScanReport() {
        return scanReport;
    }

    public TargetSulProvider getSulProvider() {
        return sulProvider;
    }

    public VulnerabilityFinderConfig getFinderConfig() {
        return finderConfig;
    }

    public void setAlphabet(NamedListAlphabet<TlsWord> alphabet) {
        this.alphabet = alphabet;
    }
}
