/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.sul;

import de.learnlib.filter.statistic.sul.SymbolCounterSUL;

public class HintedSymbolCounterSUL<I extends Object, O extends Object>
        extends SymbolCounterSUL<I, O> implements HintedSUL<I, O> {
    private final HintedSUL<I, O> sul;

    public HintedSymbolCounterSUL(String name, HintedSUL<I, O> sul) {
        super(name, sul);
        this.sul = sul;
    }

    @Override
    public O step(I in) {
        super.getStatisticalData().increment();
        return (O) stepWithHint(in, new ReceiveHint(null));
    }

    @Override
    public Object stepWithHint(Object in, ReceiveHint hint) {
        super.getStatisticalData().increment();
        return sul.stepWithHint((I) in, hint);
    }
}
