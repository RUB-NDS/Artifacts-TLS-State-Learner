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
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.tool.main.command.AbstractCommand;
import de.rub.nds.statevulnfinder.tool.main.command.CommandContext;
import de.rub.nds.statevulnfinder.tool.main.command.CommandUtil;
import java.util.LinkedList;
import java.util.List;

/** Command to list predecessors of a state. */
public class PredecessorsCommand extends AbstractCommand {

    @Override
    public String getName() {
        return "predecessors";
    }

    @Override
    public String[] getAliases() {
        return new String[] {"pc"};
    }

    @Override
    public String getDescription() {
        return "List all transitions leading to the specified state";
    }

    @Override
    public String getUsage() {
        return "predecessors <state>";
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
        int stateIndex = Integer.parseInt(args[0]);

        List<Object> stateList =
                new LinkedList<>(context.getStateMachine().getMealyMachine().getStates());
        Object soughtState = stateList.get(stateIndex);
        int loopsFound = 0;
        LOG.info("Predecessors of s{}", stateIndex);

        for (Object state : stateList) {
            for (TlsWord input : context.getStateMachine().getAlphabet()) {
                Object successor =
                        context.getStateMachine().getMealyMachine().getSuccessor(state, input);
                SulResponse output =
                        (SulResponse)
                                context.getStateMachine().getMealyMachine().getOutput(state, input);

                if (successor == soughtState) {
                    if (state == soughtState) {
                        loopsFound++;
                    } else {
                        LOG.info(
                                "s{} {} -> s{}  for {} with {}",
                                state,
                                (context.getGraphDetails() != null)
                                        ? "["
                                                + CommandUtil.resolveStateQuickSymbol(
                                                        state,
                                                        context.getStateMachine(),
                                                        context.getGraphDetails())
                                                + "]"
                                        : "",
                                successor,
                                input,
                                output);
                    }
                }
            }
        }

        if (loopsFound > 0) {
            LOG.info("Additionally, {} inputs loop when state is reached.", loopsFound);
        } else {
            LOG.info("No inputs loop within this state.");
        }
    }
}
