/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.algorithm;

import de.learnlib.api.oracle.MembershipOracle;
import de.learnlib.api.query.DefaultQuery;
import de.learnlib.oracle.equivalence.RandomWordsEQOracle;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import net.automatalib.automata.concepts.Output;
import net.automatalib.words.Word;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.checkerframework.checker.nullness.qual.Nullable;

public class CountingRandomWordsEQOracle<A extends Output<I, D>, I, D>
        extends RandomWordsEQOracle<A, I, D> {
    private static final Logger LOG = LogManager.getLogger();
    private final MembershipOracle<I, D> mqOracle;

    public CountingRandomWordsEQOracle(
            MembershipOracle<I, D> mqOracle,
            int minLength,
            int maxLength,
            int maxTests,
            Random random) {
        super(mqOracle, minLength, maxLength, maxTests, random);
        this.mqOracle = mqOracle;
    }

    @Override
    public @Nullable DefaultQuery<I, D> findCounterExample(
            A hypothesis, Collection<? extends I> inputs) {
        // Fail fast on empty inputs
        if (inputs.isEmpty()) {
            return null;
        }

        final Stream<Word<I>> testWordStream = generateTestWords(hypothesis, inputs);
        final Stream<DefaultQuery<I, D>> queryStream = testWordStream.map(DefaultQuery::new);
        List<DefaultQuery<I, D>> queries = queryStream.collect(Collectors.toList());
        DefaultQuery<I, D> firstFailing = null;
        for (DefaultQuery<I, D> query : queries) {
            mqOracle.processQuery(query);
            D hypOutput = hypothesis.computeOutput(query.getInput());
            if (!Objects.equals(hypOutput, query.getOutput())) {
                firstFailing = query;
                break;
            }
        }

        if (firstFailing != null) {
            LOG.debug(
                    "Found first contradicting query at {}/{}",
                    queries.indexOf(firstFailing),
                    queries.size());
        }

        return firstFailing;
    }
}
