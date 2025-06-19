/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.sul;

import de.learnlib.api.SUL;

public interface HintedSUL<I extends Object, O extends Object> extends SUL<I, O> {
    public O stepWithHint(I in, ReceiveHint hint);
}
