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
import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.classifier.Classifier;
import de.rub.nds.statevulnfinder.core.config.VulnerabilityFinderConfig;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import net.automatalib.automata.concepts.OutputAutomaton;
import net.automatalib.automata.transducers.MealyMachine;
import net.automatalib.words.Alphabet;
import net.automatalib.words.WordBuilder;
import org.apache.logging.log4j.LogManager;

/** Performs RandomWords tests for all states */
public class StateBoundRandomWordsEQOracle<D, A extends OutputAutomaton<?, TlsWord, ?, D>>
        implements EquivalenceOracle<A, TlsWord, D> {

    private static final org.apache.logging.log4j.Logger LOG = LogManager.getLogger();

    private static final Random random = new Random(0L);

    private final MembershipOracle<TlsWord, D> oracle;
    private final VulnerabilityFinderConfig vulnerabilityFinderConfig;

    public StateBoundRandomWordsEQOracle(
            MembershipOracle<TlsWord, D> mqOracle,
            VulnerabilityFinderConfig vulnerabilityFinderConfig,
            Alphabet<TlsWord> alphabet) {
        this.oracle = mqOracle;
        this.vulnerabilityFinderConfig = vulnerabilityFinderConfig;
    }

    @Override
    public DefaultQuery<TlsWord, D> findCounterExample(
            A hypothesis, Collection<? extends TlsWord> alphabet) {
        LOG.debug("Starting State Bound Random Words");
        MealyMachine currentMealyMachine = (MealyMachine) hypothesis;
        StateMachine currentStateMachine =
                new StateMachine(currentMealyMachine, (Alphabet) alphabet, null);
        int stateCtr = 0;
        for (Object state : currentMealyMachine.getStates()) {
            stateCtr++;
            LOG.info("EQ Testing State {}/{}", stateCtr, currentMealyMachine.getStates().size());
            List<TlsWord> pathToNode = null;
            boolean isInitialState = state == currentMealyMachine.getInitialState();
            pathToNode = getPathToState(isInitialState, currentStateMachine, state);

            if (pathToNode != null && (!pathToNode.isEmpty() || isInitialState)) {
                for (int i = 0; i < vulnerabilityFinderConfig.getNumberOfQueries(); i++) {
                    LOG.debug(
                            "EQ-Test - State {}/{} - Query {}/{}",
                            stateCtr,
                            currentMealyMachine.getStates().size(),
                            i + 1,
                            vulnerabilityFinderConfig.getNumberOfQueries());
                    List<TlsWord> fullPath =
                            extendPathWithRandomInputs(pathToNode, (Alphabet<TlsWord>) alphabet);
                    WordBuilder<TlsWord> tlsWordBuilder = new WordBuilder<>();
                    tlsWordBuilder.append(fullPath);
                    final DefaultQuery<TlsWord, D> query =
                            new DefaultQuery<>(tlsWordBuilder.toWord());

                    oracle.processQuery(query);
                    D oracleOutput = query.getOutput();
                    // trace hypothesis
                    D hypOutput = hypothesis.computeOutput(query.getInput());

                    if (!Objects.equals(oracleOutput, hypOutput)) {
                        LOG.debug("Found counterexample for state");
                        return query;
                    }
                }
            } else {
                LOG.error(
                        "Failed to find path to {} for {} during equivalence test",
                        state.toString(),
                        vulnerabilityFinderConfig.getImplementationName());
            }
        }
        LOG.debug("No counterexample found");
        return null;
    }

    private List<TlsWord> getPathToState(
            boolean isInitialState, StateMachine currentStateMachine, Object state) {
        List<TlsWord> pathToNode;
        if (isInitialState) {
            pathToNode = new LinkedList<>();
        } else {
            pathToNode =
                    Classifier.getPathToNodeResetting(
                            currentStateMachine,
                            currentStateMachine.getMealyMachine().getInitialState(),
                            state);
        }
        return pathToNode;
    }

    private List<TlsWord> extendPathWithRandomInputs(
            List<TlsWord> initialPath, Alphabet<TlsWord> alphabet) {
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
}
