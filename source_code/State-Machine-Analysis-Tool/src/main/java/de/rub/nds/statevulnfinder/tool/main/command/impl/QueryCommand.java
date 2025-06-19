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
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.tool.analysis.AnalysisUtil;
import de.rub.nds.statevulnfinder.tool.main.command.AbstractCommand;
import de.rub.nds.statevulnfinder.tool.main.command.CommandContext;
import de.rub.nds.statevulnfinder.tool.main.command.CommandUtil;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

/** Command to send inputs to host. */
public class QueryCommand extends AbstractCommand {

    @Override
    public String getName() {
        return "query";
    }

    @Override
    public String[] getAliases() {
        return new String[] {"q"};
    }

    @Override
    public String getDescription() {
        return "Send inputs to host (requires scan first). Use 'false' to disable cache";
    }

    @Override
    public String getUsage() {
        return "query <indices> [<useCache>]";
    }

    @Override
    protected boolean validateArguments(String[] args) {
        return args.length >= 1;
    }

    @Override
    protected void executeCommand(String[] args, CommandContext context) {
        if (context.getTlsServerSul() == null) {
            LOG.warn("No TLS server connection available. Run 'scan' first.");
            return;
        }

        StateMachine stateMachine = context.getStateMachine();
        boolean useCache = true;

        // Check if last argument is a boolean for cache usage
        if (args.length >= 2) {
            String lastArg = args[args.length - 1];
            if (lastArg.equalsIgnoreCase("true") || lastArg.equalsIgnoreCase("false")) {
                useCache = Boolean.parseBoolean(lastArg);
            }
        }

        List<TlsWord> inputsToSend = resolveQuerySequence(args, context);

        LOG.info(
                "Querying target with '{}', useCache:{}",
                inputsToSend.stream().map(Object::toString).collect(Collectors.joining(",")),
                useCache);

        if (useCache && context.getSulCache() != null) {
            context.getSulCache().pre();
        } else {
            context.getTlsServerSul().pre();
        }

        LOG.info("Initialized connection");
        int ctr = 0;
        List<SulResponse> responses = new LinkedList<>();

        for (TlsWord input : inputsToSend) {
            ctr++;
            SulResponse response;
            if (useCache && context.getSulCache() != null) {
                response = context.getSulCache().step(input);
            } else {
                response = context.getTlsServerSul().step(input);
            }
            responses.add(response);

            LOG.info(
                    "{}.\t [{}] \t For {} received {}",
                    ctr,
                    AnalysisUtil.getMatchesStateMachineSymbol(
                            stateMachine, inputsToSend, responses, ctr),
                    input,
                    response);

            if (input.getType() == TlsWordType.CCS
                    && context.getTlsServerSul().getState() != null) {
                LOG.info(
                        "CCS called - master secret in state is {}",
                        context.getTlsServerSul().getState().getTlsContext().getMasterSecret());
            }
        }

        if (useCache && context.getSulCache() != null) {
            context.getSulCache().post();
        } else {
            context.getTlsServerSul().post();
        }

        LOG.info("Post called for TlsSul.");
        LOG.info("!! = Response does not match obtained state machine.");
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
