/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2023 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.issue;

import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public interface StateDivergenceIssue extends GuidedEquivalenceTestIssue {

    @Override
    public default List<List<TlsWord>> getEquivalenceTestStartPaths() {
        List<TlsWord> path1 = new LinkedList<>(getPath());
        List<TlsWord> path2 = new LinkedList<>(getPath());
        path1.add(getFirstWord());
        path2.add(getSecondWord());
        return Arrays.asList(path1, path2);
    }

    public TlsWord getFirstWord();

    public TlsWord getSecondWord();

    public List<TlsWord> getPath();
}
