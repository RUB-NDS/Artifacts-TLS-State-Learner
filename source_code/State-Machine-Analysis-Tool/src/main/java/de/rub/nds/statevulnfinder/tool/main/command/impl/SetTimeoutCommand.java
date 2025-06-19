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

/** Command to set the timeout for queries. */
public class SetTimeoutCommand extends AbstractCommand {

    @Override
    public String getName() {
        return "setTimeout";
    }

    @Override
    public String getDescription() {
        return "Set the timeout to use for the query command";
    }

    @Override
    public String getUsage() {
        return "setTimeout <timeout_ms>";
    }

    @Override
    protected boolean validateArguments(String[] args) {
        if (args.length != 1) {
            return false;
        }

        try {
            Integer.parseInt(args[0]);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    @Override
    protected void executeCommand(String[] args, CommandContext context) {
        int timeout = Integer.parseInt(args[0]);
        context.getConfig().setMinTimeout(timeout);
        LOG.info("Timeout set to {} ms", timeout);
    }
}
