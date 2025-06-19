/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.extraction;

import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.constants.VisualizationDetail;
import de.rub.nds.statevulnfinder.core.visualization.IssueSerializer;
import de.rub.nds.statevulnfinder.core.xml.MealySerializationHelper;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.logging.log4j.LogManager;

public class ResultWriter {

    private static final String VULNERABILITIES_FILE = "vulnerabilities.md";
    private static final String STATISTICS_FILE = "statistics.txt";
    private static final org.apache.logging.log4j.Logger LOG = LogManager.getLogger();

    public static void write(
            AnalysisResult analysisResult,
            String name,
            String directory,
            boolean writeOnlyCrucial) {
        File folder = new File(directory);
        folder.mkdirs();
        File statsFile = new File(folder, name + STATISTICS_FILE);
        try (FileWriter statsWriter = new FileWriter(statsFile)) {

            if (analysisResult.getExtractorResult() != null
                    && analysisResult.getExtractorResult().getLearnedModel() != null
                    && analysisResult.getExtractorResult().getLearnedModel().getMealyMachine()
                            != null) {
                File stateMachineFile;
                if (writeOnlyCrucial) {
                    LOG.info("Writing raw results to disk");
                    stateMachineFile = new File(folder, name + ".zip");
                    writeCrucialResults(stateMachineFile, name, analysisResult);
                } else {
                    stateMachineFile = new File(folder, name + ".xml");
                    MealySerializationHelper.serialize(
                            analysisResult.getExtractorResult().getLearnedModel(),
                            stateMachineFile);
                    writeDotPdfs(
                            analysisResult.getExtractorResult().getLearnedModel(),
                            analysisResult.getGraphDetails(),
                            name,
                            directory);
                }

            } else {
                LOG.error("No (complete) state machine provided - skipping serialization");
                File noStateMachineFile = new File(folder, "no-machine-" + name + ".zip");
                try {
                    noStateMachineFile.createNewFile();
                } catch (IOException e) {
                    System.err.println("Failed to create empty result file: " + e.getMessage());
                }
            }

            statsFile.createNewFile();
            statsWriter.append(analysisResult.getExtractorResult().getStatistics().toString());
            // analysisResult.getExtractorResult().getStatistics().export(statsWriter);

            if (!writeOnlyCrucial) {
                IssueSerializer vulnerabilitySerializer =
                        new IssueSerializer(analysisResult.getConfirmedVulnerabilities());
                vulnerabilitySerializer.serialize(new File(folder, VULNERABILITIES_FILE));
            }
        } catch (IOException ex) {
            LOG.error(ex);
        }
    }

    private static void writeCrucialResults(
            File stateMachineFile, String name, AnalysisResult analysisResult) {
        try (BufferedOutputStream bos =
                new BufferedOutputStream(new FileOutputStream(stateMachineFile))) {
            byte[] serialized =
                    serializeStateMachine(analysisResult.getExtractorResult().getLearnedModel());
            ZipOutputStream zipStream = new ZipOutputStream(bos);
            ZipEntry entry = new ZipEntry(name + ".xml");
            entry.setSize(serialized.length);
            zipStream.putNextEntry(entry);
            zipStream.write(serialized);
            zipStream.closeEntry();
            zipStream.close();
        } catch (IOException ex) {
            LOG.error("Failed to serialize state machine zip for {}, {}", name, ex);
        }
    }

    public static void writeDotPdfs(
            StateMachine stateMachine, GraphDetails graphDetails, String name, String directory) {
        File graphFile = new File(directory, name + "_long.dot");
        stateMachine.exportToDotAndPDF(graphFile, VisualizationDetail.LONG, graphDetails);
        graphFile = new File(directory, name + "_medium.dot");
        stateMachine.exportToDotAndPDF(graphFile, VisualizationDetail.MEDIUM, graphDetails);
        graphFile = new File(directory, name + "_short.dot");
        stateMachine.exportToDotAndPDF(graphFile, VisualizationDetail.SHORT, graphDetails);
    }

    public static byte[] serializeDot(
            AnalysisResult analysisResult, VisualizationDetail detailLevel, String name) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        try {
            OutputStreamWriter writer = new OutputStreamWriter(stream);
            analysisResult
                    .getExtractorResult()
                    .getLearnedModel()
                    .exportToDot(writer, detailLevel, analysisResult.getGraphDetails(), name);
            stream.close();
        } catch (IOException ex) {
            LOG.error("Failed to serialize DOT", ex);
        }
        return stream.toByteArray();
    }

    public static byte[] serializeStateMachine(StateMachine stateMachine) {
        return MealySerializationHelper.serialize(stateMachine);
    }

    public static void writeHypothesis(StateMachine hypothesis, String name, String directory) {
        File folder = new File(directory);
        folder.mkdirs();
        File graphFile = new File(folder, name);
        hypothesis.exportToDotAndPDF(graphFile, VisualizationDetail.LONG);
    }
}
