/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.visualization;

import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import net.automatalib.serialization.dot.DefaultDOTVisualizationHelper;
import net.automatalib.visualization.VisualizationHelper;
import net.automatalib.words.Alphabet;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Wraps the {@link ShortMealyVisualizationHelper} into a DOTVisualizationHelper. For some reason
 * both the writePreamble and writePostamble functions are unspecifiable in a
 * GaphVizualizationHelper/get lost during conversion. This class fixes this and allows us to add a
 * name to the graph.
 */
public class TLSDOTVisualizationHelper<N, E> extends DefaultDOTVisualizationHelper<N, E> {

    String title;
    Alphabet<TlsWord> alphabet;

    public TLSDOTVisualizationHelper(
            @Nullable VisualizationHelper<N, ? super E> delegate,
            String title,
            Alphabet<TlsWord> alphabet) {
        super(delegate);
        this.title = title;
        this.alphabet = alphabet;
    }

    @Override
    public void writePreamble(Appendable a) throws IOException {
        Set<String> stringSet = new HashSet<>();
        // appends the following to the dot
        // labelloc = "t"
        // label = "server-name"
        // fontsize = 30
        a.append(System.lineSeparator());
        a.append("    labelloc = \"b\"").append(System.lineSeparator());
        a.append("    label = \"Server-Name: ")
                .append(title)
                .append("\n\n Messages used during testing: \n");
        for (TlsWord word : alphabet) {
            if (!stringSet.contains(word.toString())) {
                a.append(word.toString()).append("\n");
                // dont add anything twice (for padding oracle and bleichenbacher words)
                stringSet.add(word.toString());
            }
        }
        a.append("\"").append(System.lineSeparator());

        // TESTING

        a.append("    fontsize = 30 ").append(System.lineSeparator());
    }

    @Override
    public void writePostamble(Appendable a) throws IOException {}
}
