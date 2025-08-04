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
import de.rub.nds.statevulnfinder.core.analysis.responses.ExpectedResponse;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextPropertyContainer;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.server.analysis.response.ServerExpectedResponseProvider;
import de.rub.nds.statevulnfinder.server.analysis.transition.ServerContextPropertyContainer;
import de.rub.nds.statevulnfinder.server.analysis.transition.ServerTransitionAnalyzer;
import de.rub.nds.statevulnfinder.tool.analysis.AnalysisUtil;
import de.rub.nds.statevulnfinder.tool.main.command.AbstractCommand;
import de.rub.nds.statevulnfinder.tool.main.command.CommandContext;
import de.rub.nds.statevulnfinder.tool.main.command.CommandUtil;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

/** Command to determine expected responses for the last message in a given sequence. */
public class AllowedResponsesCommand extends AbstractCommand {

    @Override
    public String getName() {
        return "allowedResponses";
    }

    @Override
    public String[] getAliases() {
        return new String[] {"ar"};
    }

    @Override
    public String getDescription() {
        return "Show expected responses for the last message in a given sequence";
    }

    @Override
    public String getUsage() {
        return "allowedResponses <indices>";
    }

    @Override
    protected boolean validateArguments(String[] args) {
        return args.length >= 1; // Require at least one argument (no empty queries)
    }

    @Override
    protected void executeCommand(String[] args, CommandContext context) {
        StateMachine stateMachine = context.getStateMachine();
        List<TlsWord> inputsToSend = resolveQuerySequence(args, context);

        if (inputsToSend.isEmpty()) {
            LOG.error("Empty query not allowed for allowedResponses command.");
            return;
        }

        LOG.info(
                "Analyzing expected responses for sequence: '{}'",
                inputsToSend.stream().map(Object::toString).collect(Collectors.joining(",")));

        // Get the last message type
        TlsWord lastMessage = inputsToSend.get(inputsToSend.size() - 1);
        TlsWordType lastMessageType = lastMessage.getType();

        LOG.info("Last message type: {}", lastMessageType.name());

        // Create a ServerTransitionAnalyzer to get context properties
        ServerTransitionAnalyzer analyzer =
                new ServerTransitionAnalyzer(inputsToSend, stateMachine);
        ContextPropertyContainer contextContainer =
                new ServerContextPropertyContainer(stateMachine);

        // Update context properties with the message sequence
        for (TlsWord message : inputsToSend) {
            contextContainer.updateContextProperties(message);
        }

        // Get all expected responses from the provider
        ServerExpectedResponseProvider responseProvider = new ServerExpectedResponseProvider();
        ExpectedResponse[] allExpectedResponses = responseProvider.getAllExpectedResponses();

        // Filter responses that apply to the last message type and current context
        List<ExpectedResponse> applicableResponses =
                Arrays.stream(allExpectedResponses)
                        .filter(response -> response.appliesTo(lastMessageType, contextContainer))
                        .collect(Collectors.toList());

        if (applicableResponses.isEmpty()) {
            LOG.info(
                    "No expected responses found for message type '{}' in current context.",
                    lastMessageType.name());
            return;
        }

        // Get the observed response for comparison
        SulResponse observedResponse = AnalysisUtil.getLastResponse(inputsToSend, stateMachine);

        LOG.info(
                "Expected responses for '{}' ({} total):",
                lastMessageType.name(),
                applicableResponses.size());

        for (int i = 0; i < applicableResponses.size(); i++) {
            ExpectedResponse expectedResponse = applicableResponses.get(i);
            boolean matchesObserved = expectedResponse.matchesObservedResponse(observedResponse);

            String matchIndicator = matchesObserved ? " ✓ MATCHES OBSERVED" : "";
            LOG.info("  {}. {}{}", i + 1, formatExpectedResponse(expectedResponse), matchIndicator);
        }

        LOG.info("");
        LOG.info("Observed response: {}", formatObservedResponse(observedResponse));
    }

    private String formatExpectedResponse(ExpectedResponse expectedResponse) {
        if (expectedResponse.getExpectedMessages().isEmpty()) {
            return "No messages expected";
        }

        return expectedResponse.getExpectedMessages().stream()
                .map(
                        expectedMsg -> {
                            String msgName = expectedMsg.getMessage().getSimpleName();
                            return expectedMsg.isRequired() ? msgName : "[" + msgName + "]";
                        })
                .collect(Collectors.joining(" + "));
    }

    private String formatObservedResponse(SulResponse response) {
        if (response.isIllegalTransitionFlag()) {
            return "IllegalTransition";
        }

        if (response.getResponseFingerprint() == null
                || response.getResponseFingerprint().getMessageList() == null
                || response.getResponseFingerprint().getMessageList().isEmpty()) {
            return "No messages";
        }

        return response.getResponseFingerprint().getMessageList().stream()
                .map(msg -> msg.getClass().getSimpleName())
                .collect(Collectors.joining(" + "));
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
