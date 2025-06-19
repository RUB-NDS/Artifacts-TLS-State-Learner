/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.main.command.impl;

import de.rub.nds.statevulnfinder.core.constants.VisualizationDetail;
import de.rub.nds.statevulnfinder.tool.main.command.AbstractCommand;
import de.rub.nds.statevulnfinder.tool.main.command.CommandContext;
import java.io.File;
import java.io.FileWriter;

/** Command to write state machine to DOT file. */
public class WriteDotCommand extends AbstractCommand {

    @Override
    public String getName() {
        return "writeDot";
    }

    @Override
    public String getDescription() {
        return "Write state machine to DOT file";
    }

    @Override
    public String getUsage() {
        return "writeDot [<detail>]";
    }

    @Override
    protected boolean validateArguments(String[] args) {
        return args.length <= 1;
    }

    @Override
    protected void executeCommand(String[] args, CommandContext context) {
        if (context.getGraphDetails() == null) {
            // Run analysis first if not already done
            LOG.info("Running analysis first...");
            context.setGraphDetails(new de.rub.nds.statevulnfinder.core.analysis.GraphDetails());
            de.rub.nds.statevulnfinder.core.analysis.Analyzer analyzer =
                    new de.rub.nds.statevulnfinder.server.extraction.TlsServerSulProvider()
                            .getAnalyzer(context.getGraphDetails());
            context.setFoundVulnerabilities(
                    analyzer.findVulnerabilities(context.getStateMachine()));
        }

        VisualizationDetail detail = VisualizationDetail.LONG;
        if (args.length > 0) {
            try {
                detail = VisualizationDetail.valueOf(args[0].toUpperCase());
            } catch (IllegalArgumentException e) {
                LOG.warn(
                        "Could not parse visualization detail level. Using default: {}",
                        detail.name());
            }
            LOG.info("Using visualization detail level: {}", detail.name());
        }

        if (context.getXmlFilePath() != null) {
            File dotFile = new File(context.getXmlFilePath().replace(".xml", ".dot"));
            try {
                context.getStateMachine()
                        .exportToDot(
                                new FileWriter(dotFile),
                                detail,
                                context.getGraphDetails(),
                                context.getXmlFilePath());
                LOG.info("DOT file written to: {}", dotFile.getAbsolutePath());
            } catch (Exception e) {
                LOG.error("Could not write dot file: {}", e.getMessage());
            }
        } else {
            LOG.warn("No XML file path found. Please load a state machine first.");
        }
    }
}
