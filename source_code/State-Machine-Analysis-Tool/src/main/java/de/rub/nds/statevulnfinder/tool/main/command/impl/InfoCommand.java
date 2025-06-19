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
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.analysis.TlsBenignStateInfo;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextProperty;
import de.rub.nds.statevulnfinder.tool.main.command.AbstractCommand;
import de.rub.nds.statevulnfinder.tool.main.command.CommandContext;
import de.rub.nds.statevulnfinder.tool.main.command.CommandUtil;
import java.util.stream.Collectors;

/** Command to get analysis information for a state. */
public class InfoCommand extends AbstractCommand {

    @Override
    public String getName() {
        return "info";
    }

    @Override
    public String[] getAliases() {
        return new String[] {"i"};
    }

    @Override
    public String getDescription() {
        return "Get analysis information for the specified state";
    }

    @Override
    public String getUsage() {
        return "info <state>";
    }

    @Override
    public boolean requiresAnalysis() {
        return true;
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
        Object state = CommandUtil.getStateByIndex(stateIndex, context.getStateMachine());
        GraphDetails graphDetails = context.getGraphDetails();

        if (graphDetails.getBenignStateInfoMap().get(state) != null) {
            TlsBenignStateInfo stateInfo = graphDetails.getBenignStateInfoMap().get(state);
            LOG.info("State s{}:", stateIndex);
            LOG.info("Names: {}", stateInfo.getNames().stream().collect(Collectors.joining(", ")));
            LOG.info(
                    "Allowed Inputs: {}",
                    stateInfo.getBenignInputs().stream()
                            .map(TlsWord::toString)
                            .collect(Collectors.joining(", ")));
            LOG.info("Version flow: {}", stateInfo.getVersionFlow());
            LOG.info(
                    "Context properties: {}",
                    stateInfo.getContextPropertiesWhenReached().stream()
                            .map(ContextProperty::name)
                            .collect(Collectors.joining(", ")));
        } else {
            LOG.info("--> s{} is not listed among benign states", stateIndex);
        }

        if (graphDetails.getErrorStates().contains(state)) {
            LOG.info(
                    "--> s{} is one of {} error states found.",
                    stateIndex,
                    graphDetails.getErrorStates().size());
        } else if (graphDetails.getIllegalTransitionLearnerState() == state) {
            LOG.info("--> s{} is the IllegalTransitionLearnerState", stateIndex);
        }
    }
}
