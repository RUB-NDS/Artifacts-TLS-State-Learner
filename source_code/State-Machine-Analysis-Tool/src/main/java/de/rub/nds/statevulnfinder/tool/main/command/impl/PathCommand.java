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
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.classifier.Classifier;
import de.rub.nds.statevulnfinder.tool.analysis.AnalysisUtil;
import de.rub.nds.statevulnfinder.tool.main.command.AbstractCommand;
import de.rub.nds.statevulnfinder.tool.main.command.CommandContext;
import de.rub.nds.statevulnfinder.tool.main.command.CommandUtil;
import java.util.List;
import java.util.stream.Collectors;

/** Command to find a path to a target state. */
public class PathCommand extends AbstractCommand {

    @Override
    public String getName() {
        return "path";
    }

    @Override
    public String[] getAliases() {
        return new String[] {"p"};
    }

    @Override
    public String getDescription() {
        return "Find a path to a target state from an optional source state";
    }

    @Override
    public String getUsage() {
        return "path <target> [<source>]";
    }

    @Override
    protected boolean validateArguments(String[] args) {
        if (args.length != 1 && args.length != 2) {
            return false;
        }

        try {
            Integer.parseInt(args[0]);
            if (args.length == 2) {
                Integer.parseInt(args[1]);
            }
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    @Override
    protected void executeCommand(String[] args, CommandContext context) {
        StateMachine stateMachine = context.getStateMachine();
        List<TlsWord> path;

        if (args.length == 1) {
            int targetState = Integer.parseInt(args[0]);
            path =
                    Classifier.getPathToNodeResetting(
                            stateMachine,
                            stateMachine.getMealyMachine().getInitialState(),
                            CommandUtil.getStateByIndex(targetState, stateMachine));

            LOG.info(
                    "{} for {}",
                    AnalysisUtil.pathToString(
                            stateMachine, path, stateMachine.getMealyMachine().getInitialState()),
                    path.size());
        } else {
            int sourceState = Integer.parseInt(args[0]);
            int targetState = Integer.parseInt(args[1]);
            path =
                    Classifier.getPathToNodeResetting(
                            stateMachine,
                            CommandUtil.getStateByIndex(sourceState, stateMachine),
                            CommandUtil.getStateByIndex(targetState, stateMachine));

            LOG.info(
                    "{} for {}",
                    AnalysisUtil.pathToString(
                            stateMachine,
                            path,
                            CommandUtil.getStateByIndex(sourceState, stateMachine)),
                    path.size());
        }

        LOG.info(
                "Access path (indices): {}",
                path.stream()
                        .map(stateMachine.getAlphabet()::getSymbolIndex)
                        .map(Object::toString)
                        .collect(Collectors.joining(",")));
        LOG.info(
                "Access path (toString): {}",
                path.stream().map(Object::toString).collect(Collectors.joining(",")));

        // Store the path in recent message sequences
        context.getRecentMessageSequences().add(path);
    }
}
