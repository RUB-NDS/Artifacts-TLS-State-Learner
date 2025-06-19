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
import java.util.List;
import java.util.stream.Collectors;

/** Command to list recently stored message sequences. */
public class MessageSequencesCommand extends AbstractCommand {

    @Override
    public String getName() {
        return "messageSequences";
    }

    @Override
    public String[] getAliases() {
        return new String[] {"ms"};
    }

    @Override
    public String getDescription() {
        return "List recently stored message sequences available for queries";
    }

    @Override
    public String getUsage() {
        return "messageSequences";
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
        int ctr = 0;
        for (List<TlsWord> path : context.getRecentMessageSequences()) {
            LOG.info(
                    "@{}: {}",
                    ctr,
                    path.stream().map(TlsWord::toString).collect(Collectors.joining(" || ")));
            ctr++;
        }

        if (ctr == 0) {
            LOG.info("No message sequences stored yet.");
        }
    }
}
