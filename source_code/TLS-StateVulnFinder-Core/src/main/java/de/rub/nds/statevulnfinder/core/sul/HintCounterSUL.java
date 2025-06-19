/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.sul;

import de.learnlib.api.statistic.StatisticData;
import de.learnlib.api.statistic.StatisticSUL;
import de.learnlib.filter.statistic.Counter;

public class HintCounterSUL<I extends Object, O extends Object>
        implements StatisticSUL<I, O>, HintedSUL<I, O> {

    private final HintedSUL sul;
    private final Counter counter;
    private final Counter stepsCounter;

    public HintCounterSUL(String name, HintedSUL<I, O> sul) {
        this.sul = sul;
        this.counter = new Counter(name, "Hints");
        this.stepsCounter = new Counter(name, "Steps");
    }

    @Override
    public void pre() {
        sul.pre();
    }

    @Override
    public void post() {
        sul.post();
    }

    @Override
    public O step(I i) {
        throw new RuntimeException("Calling step for HintCounterSUL is invalid");
    }

    @Override
    public StatisticData getStatisticalData() {
        return counter;
    }

    public Counter getCounter() {
        return counter;
    }

    public Counter getStepsCounter() {
        return stepsCounter;
    }

    @Override
    public O stepWithHint(I in, ReceiveHint hint) {
        if (hint.hasExpectation()) {
            counter.increment();
        }
        stepsCounter.increment();
        return (O) sul.stepWithHint(in, hint);
    }
}
