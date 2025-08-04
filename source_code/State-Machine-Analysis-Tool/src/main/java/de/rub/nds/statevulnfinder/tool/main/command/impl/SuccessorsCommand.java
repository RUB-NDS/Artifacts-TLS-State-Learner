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
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.tool.main.command.AbstractCommand;
import de.rub.nds.statevulnfinder.tool.main.command.CommandContext;
import de.rub.nds.statevulnfinder.tool.main.command.CommandUtil;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;

/** Command to list successors of a state. */
public class SuccessorsCommand extends AbstractCommand {

    @Override
    public String getName() {
        return "successors";
    }

    @Override
    public String[] getAliases() {
        return new String[] {"sc"};
    }

    @Override
    public String getDescription() {
        return "List successors of the specified state. Use -b for brief mode (excludes IllegalLearnerTransition and CLOSED socket responses)";
    }

    @Override
    public String getUsage() {
        return "successors [-b] <state>";
    }

    @Override
    protected boolean validateArguments(String[] args) {
        if (args.length < 1 || args.length > 2) {
            return false;
        }

        // Check if -b flag is present
        int stateArgIndex = args.length - 1;
        if (args.length == 2 && !args[0].equals("-b")) {
            return false;
        }

        try {
            Integer.parseInt(args[stateArgIndex]);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    @Override
    protected void executeCommand(String[] args, CommandContext context) {
        // Parse arguments
        boolean briefMode = false;
        int stateArgIndex = 0;

        if (args.length == 2 && args[0].equals("-b")) {
            briefMode = true;
            stateArgIndex = 1;
        }

        int state = Integer.parseInt(args[stateArgIndex]);
        StateMachine stateMachine = context.getStateMachine();

        List<Object> stateList = new LinkedList<>(stateMachine.getMealyMachine().getStates());
        if (state < 0 || state >= stateList.size()) {
            LOG.warn("State {} is out of range. Range: [0,{}]", state, stateList.size() - 1);
            return;
        }

        Object stateObject = stateList.get(state);
        LOG.info("Successors of s{}", state);

        List<TlsWord> sortedAlphabet = new LinkedList<>(stateMachine.getAlphabet());
        sortedAlphabet.sort(Comparator.comparing(Object::toString));

        for (TlsWord input : sortedAlphabet) {
            Object successorState = stateMachine.getMealyMachine().getSuccessor(stateObject, input);
            int successor = stateList.indexOf(successorState);
            SulResponse output =
                    (SulResponse) stateMachine.getMealyMachine().getOutput(stateObject, input);

            // In brief mode, skip IllegalLearnerTransition and CLOSED socket responses
            if (briefMode && shouldSkipInBriefMode(output)) {
                continue;
            }

            String quickSymbol = "";
            if (context.isGraphDetailsAnalyzed()) {
                quickSymbol =
                        " ["
                                + CommandUtil.resolveStateQuickSymbol(
                                        successorState, stateMachine, context.getGraphDetails())
                                + "]";
            }

            LOG.info("s{} -> s{}{} for {} with {}", state, successor, quickSymbol, input, output);
        }
    }

    private boolean shouldSkipInBriefMode(SulResponse output) {
        // Skip IllegalLearnerTransition
        if (output.isIllegalTransitionFlag()) {
            return true;
        }

        // Skip responses with CLOSED socket state
        if (output.getResponseFingerprint() != null
                && output.getResponseFingerprint().getSocketState() != null
                && output.getResponseFingerprint().getSocketState() == SocketState.CLOSED) {
            return true;
        }

        return false;
    }
}
