/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.analysis.responses;

import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextProperty;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextPropertyContainer;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class ExpectedResponse {

    public List<ExpectedMessage> getExpectedMessages() {
        return expectedResponses;
    }

    private final TlsWordType input;
    private final ContextProperty[] requiredContextProperties;
    private final List<ExpectedMessage> expectedResponses;
    private TlsWordType[] ignorableTypes = new TlsWordType[0];

    public ExpectedResponse(TlsWordType input, Class<? extends ProtocolMessage>... messages) {
        this.input = input;
        this.requiredContextProperties = new ContextProperty[0];
        expectedResponses =
                Arrays.asList(messages).stream()
                        .map(ExpectedMessage::new)
                        .collect(Collectors.toList());
    }

    public ExpectedResponse(
            TlsWordType input,
            ContextProperty contextPropertyCondition,
            Class<? extends ProtocolMessage>... messages) {
        this.input = input;
        this.requiredContextProperties = new ContextProperty[] {contextPropertyCondition};
        expectedResponses =
                Arrays.asList(messages).stream()
                        .map(ExpectedMessage::new)
                        .collect(Collectors.toList());
    }

    public ExpectedResponse(
            TlsWordType input,
            ContextProperty firstPropertyCondition,
            ContextProperty secondPropertyCondition,
            Class<? extends ProtocolMessage>... messages) {
        this.input = input;
        this.requiredContextProperties =
                new ContextProperty[] {firstPropertyCondition, secondPropertyCondition};
        expectedResponses =
                Arrays.asList(messages).stream()
                        .map(ExpectedMessage::new)
                        .collect(Collectors.toList());
    }

    public boolean appliesTo(TlsWordType givenInput, ContextPropertyContainer propertyContainer) {
        return TlsWordType.effectivelyEquals(givenInput, input)
                && propertyContainer.doPropertiesApply(requiredContextProperties);
    }

    public boolean matchesObservedResponse(SulResponse response) {
        List<ProtocolMessage> receivedMessages = getNonIgnorableReceivedProtocolMessages(response);
        if (!response.isIllegalTransitionFlag()) {
            if (getExpectedMessages().isEmpty() && !receivedMessages.isEmpty()) {
                return false;
            }
            int i = 0;
            for (ExpectedMessage expectedMessage : getExpectedMessages()) {
                if ((receivedMessages.size() <= i
                                || !expectedMessage
                                        .getMessage()
                                        .isAssignableFrom(receivedMessages.get(i).getClass()))
                        && expectedMessage.isRequired()) {
                    // missing required
                    return false;
                } else if (receivedMessages.size() > i
                        && expectedMessage
                                .getMessage()
                                .isAssignableFrom(receivedMessages.get(i).getClass())) {
                    // found required or optional
                    i++;
                    if (expectedMessage.isMultipleAllowed()) {
                        while (receivedMessages.size() > i + 1
                                && expectedMessage
                                        .getMessage()
                                        .isAssignableFrom(receivedMessages.get(i).getClass())) {
                            // skip over allowed duplicates
                            i++;
                        }
                    }
                }
            }
        }
        return true;
    }

    private List<ProtocolMessage> getNonIgnorableReceivedProtocolMessages(SulResponse response) {
        List<ProtocolMessage> receivedMessages =
                new LinkedList<>(response.getResponseFingerprint().getMessageList());
        receivedMessages =
                receivedMessages.stream()
                        .filter(msg -> !messageCanBeIgnored(msg))
                        .collect(Collectors.toList());
        return receivedMessages;
    }

    public TlsWordType getInput() {
        return input;
    }

    public boolean messageCanBeIgnored(ProtocolMessage messageReceived) {
        for (TlsWordType ignorableType : getIgnorableTypes()) {
            if (ignorableType == TlsWordType.NEW_SESSION_TICKET
                    && messageReceived instanceof NewSessionTicketMessage) {
                return true;
            }
            if (ignorableType == TlsWordType.ANY_APP_DATA && TlsWord.isAppData(messageReceived)) {
                return true;
            }
        }
        return false;
    }

    public TlsWordType[] getIgnorableTypes() {
        return ignorableTypes;
    }

    public void setIgnorableTypes(TlsWordType... ignorableTypes) {
        this.ignorableTypes = ignorableTypes;
    }
}
