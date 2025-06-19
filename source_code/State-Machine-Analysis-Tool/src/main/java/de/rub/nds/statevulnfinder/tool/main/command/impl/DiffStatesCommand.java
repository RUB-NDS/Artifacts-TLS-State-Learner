/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.main.command.impl;

import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.tool.analysis.AnalysisUtil;
import de.rub.nds.statevulnfinder.tool.main.command.AbstractCommand;
import de.rub.nds.statevulnfinder.tool.main.command.CommandContext;

/** Command to compare two states for differences. */
public class DiffStatesCommand extends AbstractCommand {

    @Override
    public String getName() {
        return "diffStates";
    }

    @Override
    public String[] getAliases() {
        return new String[] {"ds"};
    }

    @Override
    public String getDescription() {
        return "Compare two states for differences";
    }

    @Override
    public String getUsage() {
        return "diffStates <state1> <state2>";
    }

    @Override
    protected boolean validateArguments(String[] args) {
        if (args.length != 2) {
            return false;
        }

        try {
            Integer.parseInt(args[0]);
            Integer.parseInt(args[1]);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    @Override
    protected void executeCommand(String[] args, CommandContext context) {
        int state1 = Integer.parseInt(args[0]);
        int state2 = Integer.parseInt(args[1]);

        StateMachine stateMachine = context.getStateMachine();

        if (statesNotWithinRange(state1, state2, stateMachine)) {
            LOG.warn(
                    "Provided states are out of range. Range: [0,{}]",
                    stateMachine.getMealyMachine().getStates().size() - 1);
            return;
        }

        LOG.info("Comparing state {} to {}:", state1, state2);

        String diffResponseSummary =
                AnalysisUtil.getStateDiffResponse(stateMachine, state1, state2);
        if (!diffResponseSummary.isBlank()) {
            LOG.info("Different Response:\n{}\n", diffResponseSummary);
        }

        String diffSuccessorSummary =
                AnalysisUtil.getStateDiffSuccessors(stateMachine, state1, state2);
        if (!diffSuccessorSummary.isBlank()) {
            LOG.info("Different Successor:\n{}\n", diffSuccessorSummary);
        }

        String diffBothSummary = AnalysisUtil.getStateDiffBoth(stateMachine, state1, state2);
        if (!diffBothSummary.isBlank()) {
            LOG.info("Successor and Response Differ:\n{}\n", diffBothSummary);
        }
    }

    private boolean statesNotWithinRange(int state1, int state2, StateMachine stateMachine) {
        return state1 < 0
                || state2 < 0
                || state1 >= stateMachine.getMealyMachine().getStates().size()
                || state2 >= stateMachine.getMealyMachine().getStates().size();
    }
}
