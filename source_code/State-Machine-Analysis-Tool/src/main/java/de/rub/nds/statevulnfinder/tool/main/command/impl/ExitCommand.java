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

/** Command to exit the application. */
public class ExitCommand extends AbstractCommand {

    @Override
    public String getName() {
        return "exit";
    }

    @Override
    public String[] getAliases() {
        return new String[] {"quit"};
    }

    @Override
    public String getDescription() {
        return "Exit the application";
    }

    @Override
    public String getUsage() {
        return "exit";
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
        LOG.info("Exiting application.");
        System.exit(0);
    }
}
