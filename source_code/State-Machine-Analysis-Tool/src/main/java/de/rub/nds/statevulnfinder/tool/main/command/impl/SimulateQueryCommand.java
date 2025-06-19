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
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

/** Command to simulate output for inputs based on the state machine. */
public class SimulateQueryCommand extends AbstractCommand {

    @Override
    public String getName() {
        return "simQuery";
    }

    @Override
    public String[] getAliases() {
        return new String[] {"sq"};
    }

    @Override
    public String getDescription() {
        return "Simulate output for inputs based on the state machine";
    }

    @Override
    public String getUsage() {
        return "simQuery <indices>";
    }

    @Override
    protected boolean validateArguments(String[] args) {
        return args.length >= 1;
    }

    @Override
    protected void executeCommand(String[] args, CommandContext context) {
        StateMachine stateMachine = context.getStateMachine();
        List<Object> stateList = new LinkedList<>(stateMachine.getMealyMachine().getStates());
        List<TlsWord> inputsToSend = resolveQuerySequence(args, context);

        Object state = stateMachine.getMealyMachine().getInitialState();
        int ctr = 0;

        LOG.info(
                "Simulating query for target with '{}'",
                inputsToSend.stream().map(Object::toString).collect(Collectors.joining(",")));

        for (TlsWord input : inputsToSend) {
            ctr++;
            SulResponse response =
                    (SulResponse) stateMachine.getMealyMachine().getOutput(state, input);
            Object lastState = state;
            state = stateMachine.getMealyMachine().getSuccessor(state, input);

            String quickSymbol = "";
            if (context.isGraphDetailsAnalyzed()) {
                quickSymbol =
                        CommandUtil.resolveStateQuickSymbol(
                                state, stateMachine, context.getGraphDetails());
            }

            LOG.info(
                    "{}.\t For {} received {} (s{} -> s{} [{}])",
                    ctr,
                    input,
                    response,
                    stateList.indexOf(lastState),
                    stateList.indexOf(state),
                    quickSymbol);
        }
    }

    private List<TlsWord> resolveQuerySequence(String[] args, CommandContext context) {
        List<TlsWord> inputsToSend;
        if (args.length > 0 && args[0].startsWith("@")) {
            int sequenceIndex = Integer.parseInt(args[0].replace("@", ""));
            inputsToSend = getMessageSequence(sequenceIndex, context);
        } else {
            inputsToSend = CommandUtil.parseInputs(args, context.getStateMachine());
        }
        return inputsToSend;
    }

    private List<TlsWord> getMessageSequence(int index, CommandContext context) {
        if (index >= 0 && index < context.getRecentMessageSequences().size()) {
            return context.getRecentMessageSequences().get(index);
        }
        LOG.warn("Invalid message sequence index {}. Returning empty path.", index);
        return new LinkedList<>();
    }
}
