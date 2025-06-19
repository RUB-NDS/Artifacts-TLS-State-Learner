/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.main.command.impl;

import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.tool.main.command.AbstractCommand;
import de.rub.nds.statevulnfinder.tool.main.command.CommandContext;

/** Command to print the alphabet of the loaded state machine. */
public class AlphabetCommand extends AbstractCommand {

    @Override
    public String getName() {
        return "alphabet";
    }

    @Override
    public String getDescription() {
        return "Print the alphabet of the loaded state machine";
    }

    @Override
    public String getUsage() {
        return "alphabet";
    }

    @Override
    protected boolean validateArguments(String[] args) {
        return args.length == 0;
    }

    @Override
    protected void executeCommand(String[] args, CommandContext context) {
        LOG.info("Serialized alphabet:");
        int ctr = 0;
        for (TlsWord input : context.getStateMachine().getAlphabet()) {
            LOG.info("[{}]\t{}", ctr, input.toString());
            ctr += 1;
        }
    }
}
