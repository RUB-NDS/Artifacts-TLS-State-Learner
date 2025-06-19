/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.sul;

import de.learnlib.filter.statistic.sul.ResetCounterSUL;

public class HintedResetCounterSUL<I extends Object, O extends Object> extends ResetCounterSUL<I, O>
        implements HintedSUL<I, O> {
    private final HintedSUL<I, O> sul;

    public HintedResetCounterSUL(String name, HintedSUL<I, O> sul) {
        super(name, sul);
        this.sul = sul;
    }

    @Override
    public O step(I in) {
        return (O) stepWithHint(in, new ReceiveHint(null));
    }

    @Override
    public Object stepWithHint(Object in, ReceiveHint hint) {
        return sul.stepWithHint((I) in, hint);
    }
}
