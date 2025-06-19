/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.xml;

import de.learnlib.algorithms.ttt.base.TTTState;
import de.learnlib.algorithms.ttt.mealy.TTTTransitionMealy;
import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.config.VulnerabilityFinderConfig;
import jakarta.xml.bind.JAXBException;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.util.Map;
import net.automatalib.automata.graphs.TransitionEdge;
import net.automatalib.automata.transducers.MealyMachine;
import net.automatalib.automata.transducers.TransitionOutputAutomaton;
import net.automatalib.automata.transducers.impl.FastMealy;
import net.automatalib.automata.visualization.AutomatonVisualizationHelper;
import net.automatalib.serialization.InputModelData;
import net.automatalib.serialization.InputModelDeserializer;
import net.automatalib.serialization.dot.DOTParsers;
import net.automatalib.serialization.dot.GraphDOT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MealySerializationHelper<S, T>
        extends AutomatonVisualizationHelper<
                S, TlsWord, T, TransitionOutputAutomaton<S, TlsWord, T, SulResponse>> {
    private static Logger LOGGER = LogManager.getLogger(MealySerializationHelper.class);

    public MealySerializationHelper(MealyMachine automaton) {
        super(automaton);
    }

    @Override
    public boolean getEdgeProperties(
            S src, TransitionEdge<TlsWord, T> edge, S tgt, Map<String, String> properties) {
        if (!super.getEdgeProperties(src, edge, tgt, properties)) {
            return false;
        }
        TlsWord input = edge.getInput();
        SulResponse output = automaton.getTransitionOutput(edge.getTransition());
        try {
            String label = EdgeLabelIO.write(new XmlEdgeLabel(input, output));
            properties.put(EdgeAttrs.LABEL, label);
        } catch (JAXBException | IOException e) {
            LOGGER.error("Failed to serialize: {}", e);
        } catch (Exception e) {
            LOGGER.error("Failed to serialize with unexpected exception: {}", e);
        }
        return true;
    }

    public static void serialize(StateMachine machine, File toFile) {
        try {
            FileWriter outWriter = new FileWriter(toFile);
            MealySerializationHelper<TTTState, TTTTransitionMealy> helper =
                    new MealySerializationHelper<>(machine.getMealyMachine());
            if (machine.getMealyMachine() != null) {
                GraphDOT.write(machine.getMealyMachine(), machine.getAlphabet(), outWriter, helper);
            } else {
                LOGGER.error("No state machine obtained - can not serialize");
            }
            outWriter.close();
        } catch (IOException e) {
            LOGGER.error("Failed to serialize", e);
        }
    }

    public static byte[] serialize(StateMachine machine) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        OutputStreamWriter outWriter = new OutputStreamWriter(stream);
        if (machine.getMealyMachine() != null) {
            try {
                MealySerializationHelper<TTTState, TTTTransitionMealy> helper =
                        new MealySerializationHelper<>(machine.getMealyMachine());
                GraphDOT.write(machine.getMealyMachine(), machine.getAlphabet(), outWriter, helper);
                outWriter.close();
                stream.close();
            } catch (IOException ex) {
                LOGGER.error("Failed to serialize", ex);
            }
        } else {
            LOGGER.error("No state machine obtained - can not serialize");
        }

        return stream.toByteArray();
    }

    public static StateMachine deserialize(InputStream fromStream, VulnerabilityFinderConfig config)
            throws IOException {
        InputModelDeserializer<TlsWord, FastMealy<TlsWord, SulResponse>> parser =
                DOTParsers.mealy(EdgeParser::parse);
        InputModelData<TlsWord, FastMealy<TlsWord, SulResponse>> modelData =
                parser.readModel(fromStream);
        return new StateMachine(modelData.model, modelData.alphabet, config);
    }
}
