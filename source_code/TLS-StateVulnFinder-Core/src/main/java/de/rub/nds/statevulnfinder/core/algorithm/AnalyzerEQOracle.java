/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.algorithm;

import de.learnlib.api.oracle.EquivalenceOracle;
import de.learnlib.api.oracle.MembershipOracle;
import de.learnlib.api.query.DefaultQuery;
import de.learnlib.oracle.equivalence.RandomWordsEQOracle;
import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.VulnerabilityFinder;
import de.rub.nds.statevulnfinder.core.algorithm.exception.LimitExceededException;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.config.VulnerabilityFinderConfig;
import de.rub.nds.statevulnfinder.core.extraction.TLSConflictException;
import de.rub.nds.statevulnfinder.core.issue.GuidedEquivalenceTestIssue;
import de.rub.nds.statevulnfinder.core.issue.Path;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.stream.Collectors;
import javax.annotation.Nullable;
import net.automatalib.automata.concepts.OutputAutomaton;
import net.automatalib.automata.transducers.MealyMachine;
import net.automatalib.words.Alphabet;
import net.automatalib.words.WordBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Refines hypotheses by rechecking any vulnerability path found by the analyzer. The idea is to
 * check the learned model against any found vulnerabilities to make sure that any found
 * vulnerability is indeed correct in the model. Borrows a lot of code from {@link
 * RandomWordsEQOracle}.
 */
public class AnalyzerEQOracle<D, A extends OutputAutomaton<?, TlsWord, ?, D>>
        implements EquivalenceOracle<A, TlsWord, D> {

    private static final Logger LOG = LogManager.getLogger();

    private final MembershipOracle<TlsWord, D> oracle;
    private final VulnerabilityFinderConfig vulnerabilityFinderConfig;
    private final Alphabet<TlsWord> alphabet;
    private final Random random = new Random(0L);

    public AnalyzerEQOracle(
            MembershipOracle<TlsWord, D> mqOracle,
            VulnerabilityFinderConfig vulnerabilityFinderConfig,
            Alphabet<TlsWord> alphabet) {
        this.oracle = mqOracle;
        this.vulnerabilityFinderConfig = vulnerabilityFinderConfig;
        this.alphabet = alphabet;
    }

    @Nullable
    @Override
    public DefaultQuery<TlsWord, D> findCounterExample(
            A hypothesis, Collection<? extends TlsWord> inputs) {
        // Fail fast on empty inputs
        if (inputs.isEmpty()) {
            LOG.warn(
                    "Passed empty set of inputs to equivalence oracle; no counterexample can be found!");
            return null;
        }

        List<StateMachineIssue> vulnerabilitiesToConfirm = collectVulnerabilities(hypothesis);
        List<StateMachineIssue> randomEQConfirmable =
                vulnerabilitiesToConfirm.stream()
                        .filter(vuln -> vuln instanceof GuidedEquivalenceTestIssue)
                        .collect(Collectors.toList());
        List<StateMachineIssue> pathConfirmable = new LinkedList<>(vulnerabilitiesToConfirm);
        pathConfirmable.removeAll(randomEQConfirmable);

        DefaultQuery<TlsWord, D> query = findPathCounterExample(pathConfirmable, hypothesis);
        if (query != null) {
            return query;
        }

        return findGuidedEQTestCounterExample(randomEQConfirmable, hypothesis);
    }

    private DefaultQuery<TlsWord, D> findPathCounterExample(
            List<StateMachineIssue> pathsToConfirm, A hypothesis) {
        for (StateMachineIssue vulnerability : pathsToConfirm) {
            List<TlsWord> tlsWords = vulnerability.getPath();
            if (tlsWords.isEmpty()) {
                // we ignore empty accessSequences
                continue;
            }
            EQTestResult eqTestResult = testVulnerability(tlsWords, hypothesis);
            if (eqTestResult.isContradictsHypothesis()) {
                return eqTestResult.getIoQuery();
            }
        }
        return null;
    }

    private DefaultQuery<TlsWord, D> findGuidedEQTestCounterExample(
            List<StateMachineIssue> vulnerabilities, A hypothesis) {
        for (StateMachineIssue vulnerability : vulnerabilities) {
            List<List<TlsWord>> initialPaths =
                    ((GuidedEquivalenceTestIssue) vulnerability).getEquivalenceTestStartPaths();
            for (List<TlsWord> path : initialPaths) {
                for (int i = 0; i < vulnerabilityFinderConfig.getNumberOfGuidedQueries(); i++) {
                    List<TlsWord> extendedPath = extendPathWithRandomInputs(path);
                    EQTestResult eqTestResult = testVulnerability(extendedPath, hypothesis);
                    if (eqTestResult.isContradictsHypothesis()) {
                        LOG.info(
                                "Found counter example for {} during guided EQ Test after {} iterations",
                                vulnerabilityFinderConfig.getImplementationName(),
                                i);
                        return eqTestResult.getIoQuery();
                    }
                }
            }
        }
        return null;
    }

    private List<StateMachineIssue> collectVulnerabilities(A hypothesis) {
        // initialize the vulnerability finder
        VulnerabilityFinder vulnerabilityFinder =
                vulnerabilityFinderConfig.createVulnerabilityFinder();
        List<StateMachineIssue> vulnerabilityList =
                vulnerabilityFinder.findVulnerabilities(
                        new StateMachine(
                                (MealyMachine) hypothesis, alphabet, vulnerabilityFinderConfig));
        List<StateMachineIssue> pathsToConfirm;
        if (vulnerabilityList.size() > 1000) {
            pathsToConfirm = vulnerabilityList;
        } else {
            pathsToConfirm = getMinimumPaths(vulnerabilityList);
        }
        return pathsToConfirm;
    }

    /**
     * Tests all given vulnerabilities based on a hypothesis for when we aborted learning
     *
     * @param assumedVulnerabilities The vulnerabilities assumed based on analysis of the hypothesis
     * @param latestHypothesis The hypothesis used for equivalence tests
     * @return The list of confirmed vulnerabilities
     */
    public List<StateMachineIssue> confirmVulnerabilities(
            List<StateMachineIssue> assumedVulnerabilities, A latestHypothesis) {
        List<StateMachineIssue> confirmedVulnerabilities = new LinkedList<>();
        for (StateMachineIssue vulnerability : assumedVulnerabilities) {
            try {
                EQTestResult eqTestResult =
                        testVulnerability(vulnerability.getPath(), latestHypothesis);
                if (!eqTestResult.isContradictsHypothesis()) {
                    confirmedVulnerabilities.add(vulnerability);
                }
            } catch (TLSConflictException ignored) {
            } catch (LimitExceededException limitException) {
                if (limitException.stopImmediately()) {
                    // we probably got blacklisted
                    return confirmedVulnerabilities;
                }
            }
        }
        return confirmedVulnerabilities;
    }

    private EQTestResult testVulnerability(List<TlsWord> tlsWords, A hypothesis) {
        // cast all those TlsWords to words using a wordBuilder. This seems unnecessarily complex
        // but works
        WordBuilder<TlsWord> tlsWordBuilder = new WordBuilder<>();
        tlsWordBuilder.append(tlsWords);
        final DefaultQuery<TlsWord, D> query = new DefaultQuery<>(tlsWordBuilder.toWord());

        oracle.processQuery(query);
        D oracleOutput = query.getOutput();
        // trace hypothesis
        D hypOutput = hypothesis.computeOutput(query.getInput());

        return new EQTestResult(query, !Objects.equals(oracleOutput, hypOutput));
    }

    private List<StateMachineIssue> getMinimumPaths(List<StateMachineIssue> vulnerabilityList) {
        List<StateMachineIssue> relevantPaths = new LinkedList<>(vulnerabilityList);

        for (int i = 0; i < relevantPaths.size(); i++) {
            Path currentPath = relevantPaths.get(i);
            for (int j = i + 1; j < relevantPaths.size(); j++) {
                if (pathIsPrefixOrEqual(currentPath, relevantPaths.get(j))) {
                    relevantPaths.remove(i);
                    i--;
                    break;
                } else if (pathIsPrefixOrEqual(relevantPaths.get(j), currentPath)) {
                    relevantPaths.remove(j);
                    j--;
                }
            }
        }
        return relevantPaths;
    }

    private boolean pathIsPrefixOrEqual(Path prefix, Path comparator) {
        if (prefix.getPath().size() > comparator.getPath().size()) {
            return false;
        }
        for (int i = 0; i < prefix.getPath().size(); i++) {
            if (!prefix.getPath().get(i).equals(comparator.getPath().get(i))) {
                return false;
            }
        }
        return true;
    }

    private List<TlsWord> extendPathWithRandomInputs(List<TlsWord> initialPath) {
        List<TlsWord> newPath = new LinkedList<>(initialPath);
        int wordsToAdd =
                random.nextInt(
                        vulnerabilityFinderConfig.getMaxLength()
                                - vulnerabilityFinderConfig.getMinLength());
        for (int i = 0; i < wordsToAdd; i++) {
            TlsWord additionalInput = alphabet.getSymbol(random.nextInt(alphabet.size()));
            newPath.add(additionalInput);
        }
        return newPath;
    }

    private class EQTestResult {

        private final DefaultQuery<TlsWord, D> ioQuery;
        private final boolean contradictsHypothesis;

        public EQTestResult(DefaultQuery<TlsWord, D> ioQuery, boolean contradictsHypothesis) {
            this.ioQuery = ioQuery;
            this.contradictsHypothesis = contradictsHypothesis;
        }

        public DefaultQuery<TlsWord, D> getIoQuery() {
            return ioQuery;
        }

        public boolean isContradictsHypothesis() {
            return contradictsHypothesis;
        }
    }
}
