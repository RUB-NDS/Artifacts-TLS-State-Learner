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
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.tool.main.command.AbstractCommand;
import de.rub.nds.statevulnfinder.tool.main.command.CommandContext;
import de.rub.nds.statevulnfinder.tool.main.command.CommandUtil;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

/** Command to list overview of analysis information for all states. */
public class ListStatesCommand extends AbstractCommand {

    @Override
    public String getName() {
        return "listStates";
    }

    @Override
    public String[] getAliases() {
        return new String[] {"ls"};
    }

    @Override
    public String getDescription() {
        return "List overview of analysis information for all states";
    }

    @Override
    public String getUsage() {
        return "listStates";
    }

    @Override
    public boolean requiresAnalysis() {
        return true;
    }

    @Override
    protected boolean validateArguments(String[] args) {
        return args.length == 0;
    }

    @Override
    protected void executeCommand(String[] args, CommandContext context) {
        StateMachine stateMachine = context.getStateMachine();
        GraphDetails graphDetails = context.getGraphDetails();

        List<Object> stateList = new LinkedList<>(stateMachine.getMealyMachine().getStates());
        LOG.info("Overview of States:");

        for (Object state : stateList) {
            LOG.info(
                    "s{}\t{}\t{}",
                    stateList.indexOf(state),
                    CommandUtil.resolveStateQuickSymbol(state, stateMachine, graphDetails),
                    resolveStateQuickInfo(state, stateMachine, graphDetails));
        }

        LOG.info(
                "T = Terminal, all inputs except for connection reset lead to same state or to error state");
        LOG.info(
                "E = Error state, all inputs except for connection reset lead to same state or to error state");
        LOG.info("B = Part of Bleichenbacher flow (expected to fail with Finished)");
        LOG.info("R = Can resume from here with Reset Connection + Resuming CH");
    }

    private String resolveStateQuickInfo(
            Object state, StateMachine stateMachine, GraphDetails graphDetails) {
        List<String> stateNames = new LinkedList<>();

        if (stateMachine.getMealyMachine().getInitialState() == state) {
            stateNames.add("[Initial]");
        }

        if (graphDetails.getErrorStates().contains(state)) {
            stateNames.add("[Error State]");
        }

        if (graphDetails.getIllegalTransitionLearnerState() == state) {
            stateNames.add("[Artificial Sink State]");
        }

        if (graphDetails.getBenignStateInfoMap().get(state) != null) {
            stateNames.addAll(graphDetails.getBenignStateInfoMap().get(state).getNames());
        }

        if (stateNames.isEmpty()) {
            stateNames.add("[Unexpected]");
        }

        return stateNames.stream().collect(Collectors.joining(", "));
    }
}
