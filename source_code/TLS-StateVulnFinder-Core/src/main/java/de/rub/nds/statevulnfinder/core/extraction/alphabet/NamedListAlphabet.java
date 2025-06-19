/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.extraction.alphabet;

import java.util.List;
import net.automatalib.words.impl.ListAlphabet;

/** A ListAlphabet with an assigned name */
public class NamedListAlphabet<I> extends ListAlphabet<I> {

    private final String name;

    public NamedListAlphabet(List<? extends I> list) {
        super(list);
        this.name = "unspecified";
    }

    public NamedListAlphabet(List<? extends I> list, String name) {
        super(list);
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
