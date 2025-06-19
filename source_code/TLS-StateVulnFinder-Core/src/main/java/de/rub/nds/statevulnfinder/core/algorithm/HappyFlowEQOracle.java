/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.algorithm;

import de.learnlib.api.oracle.EquivalenceOracle;
import de.learnlib.api.oracle.MembershipOracle;
import de.learnlib.api.query.DefaultQuery;
import de.rub.nds.statevulnfinder.core.algorithm.words.*;
import java.util.*;
import net.automatalib.automata.concepts.OutputAutomaton;
import net.automatalib.words.Alphabet;
import net.automatalib.words.WordBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.checkerframework.checker.nullness.qual.Nullable;

public abstract class HappyFlowEQOracle<D, A extends OutputAutomaton<?, TlsWord, ?, D>>
        implements EquivalenceOracle<A, TlsWord, D> {

    private static final Logger LOG = LogManager.getLogger();

    private final MembershipOracle<TlsWord, D> oracle;
    private final Alphabet<TlsWord> alphabet;

    public HappyFlowEQOracle(MembershipOracle<TlsWord, D> mqOracle, Alphabet<TlsWord> alphabet) {
        this.oracle = mqOracle;
        this.alphabet = alphabet;
    }

    @Override
    public @Nullable DefaultQuery<TlsWord, D> findCounterExample(
            A hypothesis, Collection<? extends TlsWord> inputs) {
        List<List<TlsWord>> flowsToExecute = new LinkedList<>();
        flowsToExecute.addAll(getHappyFlows());
        flowsToExecute.addAll(getSanityFlows());

        for (List<TlsWord> tlsWordList : flowsToExecute) {
            // ignore unsupported happyFlows
            if (tlsWordList == null || tlsWordList.isEmpty()) {
                continue;
            }
            // query the happyflow twice to trigger renegotiation
            List<TlsWord> tlsWords = new LinkedList<>(tlsWordList);
            tlsWords.addAll(tlsWordList);

            final Collection<DefaultQuery<TlsWord, D>> queryBatch = new ArrayList<>();
            // cast all those TlsWords to words using a wordBuilder. This seems unnecessarily
            // complex but works
            WordBuilder<TlsWord> tlsWordBuilder = new WordBuilder<>();
            tlsWordBuilder.append(tlsWords);
            final DefaultQuery<TlsWord, D> query = new DefaultQuery<>(tlsWordBuilder.toWord());
            queryBatch.add(query);

            oracle.processQueries(queryBatch);

            final DefaultQuery<TlsWord, D> ioQuery = queryBatch.iterator().next();
            D oracleOutput = ioQuery.getOutput();

            // trace hypothesis
            D hypOutput = hypothesis.computeOutput(ioQuery.getInput());

            // compare output of hypothesis and oracle
            if (!Objects.equals(oracleOutput, hypOutput)) {
                return ioQuery;
            }
            queryBatch.clear();
        }
        return null;
    }

    protected abstract List<List<TlsWord>> getHappyFlows();

    protected List<List<TlsWord>> getSanityFlows() {
        return new LinkedList<>();
    }

    public Alphabet<TlsWord> getAlphabet() {
        return alphabet;
    }
}
