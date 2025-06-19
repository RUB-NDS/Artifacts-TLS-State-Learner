/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core;

import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.config.VulnerabilityFinderConfig;
import de.rub.nds.statevulnfinder.core.constants.VisualizationDetail;
import de.rub.nds.statevulnfinder.core.visualization.ShortMealyVisualizationHelper;
import de.rub.nds.statevulnfinder.core.visualization.TLSDOTVisualizationHelper;
import java.io.*;
import net.automatalib.automata.transducers.MealyMachine;
import net.automatalib.serialization.dot.GraphDOT;
import net.automatalib.words.Alphabet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StateMachine {
    private static final Logger LOG = LogManager.getLogger();

    private MealyMachine mealyMachine;

    private VulnerabilityFinderConfig config;

    private Alphabet<TlsWord> alphabet;

    public StateMachine(
            MealyMachine mealyMachine,
            Alphabet<TlsWord> alphabet,
            VulnerabilityFinderConfig config) {
        this.mealyMachine = mealyMachine;
        this.alphabet = alphabet;
        this.config = config;
    }

    public MealyMachine getMealyMachine() {
        return mealyMachine;
    }

    public void setMealyMachine(MealyMachine mealyMachine) {
        this.mealyMachine = mealyMachine;
    }

    public Alphabet<TlsWord> getAlphabet() {
        return alphabet;
    }

    public void setAlphabet(Alphabet<TlsWord> alphabet) {
        this.alphabet = alphabet;
    }

    public void exportToDotAndPDF(File graphFile, VisualizationDetail detail) {
        exportToDotAndPDF(graphFile, detail, new GraphDetails());
    }

    /**
     * Exports the hypothesis to the supplied file and generates a corresponding viewable .pdf
     * model.
     *
     * @param graphFile The file to write to
     * @param detail The level of detail for the PDF and DOT file
     * @param graphDetails The meta information for the extracted state machine
     */
    public void exportToDotAndPDF(
            File graphFile, VisualizationDetail detail, GraphDetails graphDetails) {
        try {
            graphFile.createNewFile();
            exportToDot(
                    new FileWriter(graphFile),
                    detail,
                    graphDetails,
                    getConfig().getImplementationName());
            String fileName = graphFile.getAbsolutePath();
            fileName = fileName.substring(0, fileName.length() - 4);
            Runtime.getRuntime()
                    .exec("dot -Tpdf " + graphFile.getAbsolutePath() + " -o " + fileName + ".pdf");
        } catch (IOException e) {
            LOG.warn("Could not export model: {}", e);
        }
    }

    public void exportToDot(Writer writer, VisualizationDetail detail, String implementationName) {
        exportToDot(writer, detail, new GraphDetails(), implementationName);
    }

    public void exportToDot(
            Writer writer,
            VisualizationDetail detail,
            GraphDetails graphDetails,
            String implementationName) {
        try {
            GraphDOT.write(
                    mealyMachine.transitionGraphView(alphabet),
                    writer,
                    new TLSDOTVisualizationHelper<>(
                            new ShortMealyVisualizationHelper(
                                    mealyMachine, graphDetails, detail, alphabet),
                            implementationName,
                            alphabet));
            writer.close();
        } catch (IOException e) {
            LOG.warn("Could not export model!");
        }
    }

    public String toString(VisualizationDetail detail) {
        StringWriter sw = new StringWriter();
        exportToDot(sw, detail, config.getImplementationName());
        return sw.toString();
    }

    public VulnerabilityFinderConfig getConfig() {
        return config;
    }

    public void setVulnerabilityFinderConfig(VulnerabilityFinderConfig config) {
        this.config = config;
    }
}
