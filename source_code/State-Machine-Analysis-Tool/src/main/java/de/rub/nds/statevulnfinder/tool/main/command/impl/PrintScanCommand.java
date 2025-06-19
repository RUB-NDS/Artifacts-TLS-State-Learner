/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.main.command.impl;

import de.rub.nds.statevulnfinder.tool.main.command.AbstractCommand;
import de.rub.nds.statevulnfinder.tool.main.command.CommandContext;

/** Command to print the obtained scan report. */
public class PrintScanCommand extends AbstractCommand {

    @Override
    public String getName() {
        return "printScan";
    }

    @Override
    public String getDescription() {
        return "Print the obtained scan report";
    }

    @Override
    public String getUsage() {
        return "printScan";
    }

    @Override
    public boolean requiresStateMachine() {
        return false;
    }

    @Override
    protected boolean validateArguments(String[] args) {
        return args.length == 0;
    }

    @Override
    protected void executeCommand(String[] args, CommandContext context) {
        if (!context.getWrittenScanReport().isBlank()) {
            LOG.info(context.getWrittenScanReport());
        } else {
            LOG.warn("No written ScanReport found. Use 'scan' first.");
        }
    }
}
