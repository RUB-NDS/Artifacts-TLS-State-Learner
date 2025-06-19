/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.analysis.transitions;

import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.algorithm.words.ResetConnectionWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.responses.ExpectedResponse;
import de.rub.nds.statevulnfinder.core.analysis.responses.ExpectedResponseProvider;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Analyzes the previous transitions and determines its ContextProperties
 *
 * @author marcel
 */
public abstract class TransitionAnalyzer {

    private final List<TlsWord> messagesSent;
    protected final StateMachine stateMachine;

    public TransitionAnalyzer(List<TlsWord> messagesSent, StateMachine stateMachine) {
        this.messagesSent = Collections.unmodifiableList(new ArrayList<>(messagesSent));
        this.stateMachine = stateMachine;
    }

    protected TransitionAnalyzer getPreviousState() {
        LinkedList<TlsWord> formerMessagesSent = new LinkedList<>(getMessagesSent());
        formerMessagesSent.remove(formerMessagesSent.size() - 1);
        return createInstance(formerMessagesSent, stateMachine);
    }

    protected TransitionAnalyzer getAlternativeState(TlsWord alternativeInput) {
        LinkedList<TlsWord> alternativeMessageFlow = new LinkedList<>(getMessagesSent());
        alternativeMessageFlow.remove(alternativeMessageFlow.size() - 1);
        alternativeMessageFlow.add(alternativeInput);
        return createInstance(alternativeMessageFlow, stateMachine);
    }

    protected abstract TransitionAnalyzer createInstance(
            List<TlsWord> messagesSent, StateMachine stateMachine);

    protected abstract ExpectedResponseProvider getExpectedResponseProvider();

    protected abstract TlsLetterChainProvider getLetterChainProvider();

    /**
     * Checks if all messages belong to a benign flow. Note that we must abort upon the first
     * non-compliance as the ContextProperties may be invalid otherwise.
     *
     * @return analysis result
     */
    public boolean isBenignFlow() {
        ContextPropertyContainer propertyContainer = getContextPropertyContainer(stateMachine);
        TlsWordType previousSent = null;

        for (TlsWord messageSent : getMessagesSent()) {
            if (!isAllowedSuccessor(previousSent, messageSent.getType(), propertyContainer)) {
                return false;
            }
            propertyContainer.updateContextProperties(messageSent);
            previousSent = messageSent.getType();
        }
        return true;
    }

    /**
     * Checks if messages after a reset constitute a benign flow.
     *
     * @return
     */
    public boolean isEffectivelyBenignFlow() {
        ContextPropertyContainer propertyContainer = getContextPropertyContainer(stateMachine);
        int lastResetIndex = getMessagesSent().lastIndexOf(new ResetConnectionWord());
        TlsWordType previousSent = null;
        List<TlsWord> partialMessageStack = new LinkedList<>();

        for (int i = 0; i < getMessagesSent().size(); i++) {
            TlsWord messageSent = getMessagesSent().get(i);
            if (previousSent != null) {
                previousSent = getEffectiveLastSent(propertyContainer, partialMessageStack);
            }
            if (!isAllowedSuccessor(previousSent, messageSent.getType(), propertyContainer)
                    && i > lastResetIndex) {
                return false;
            }
            propertyContainer.updateContextProperties(messageSent);
            previousSent = messageSent.getType();
            partialMessageStack.add(messageSent);
        }
        return true;
    }

    /**
     * Determines if we expected that the most recently sent message results in a loop. Effectively
     * we check if the permitted messages are the same as before.
     *
     * @return true if expected loop
     */
    public boolean lastInputMayLoop() {
        if (getMessagesSent().isEmpty()) {
            throw new IllegalArgumentException(
                    "Must not check for allowed loops with empty message stack");
        }
        TransitionAnalyzer previousState = getPreviousState();
        return previousState.getAllowedSuccessors().equals(getAllowedSuccessors());
    }

    /**
     * Determines if any word from the input alphabet that matches the given type results in equal
     * successor inputs as the last input for the current messagesSent.
     *
     * @param type the input type to be used instead of actual last input type
     * @return true if allowed successors are equal
     */
    public boolean yieldsEqualSuccessorsAsLast(TlsWordType type) {
        if (getMessagesSent().isEmpty()) {
            throw new IllegalArgumentException(
                    "Must not check for equal successors with empty message stack");
        }
        List<TlsWord> applicableForType =
                stateMachine.getAlphabet().stream()
                        .filter(letter -> TlsWordType.effectivelyEquals(letter.getType(), type))
                        .collect(Collectors.toList());
        List<TlsWord> presentFlowAllowedSuccessors = getAllowedSuccessors();
        for (TlsWord applicableWord : applicableForType) {
            TransitionAnalyzer alternativeState = getAlternativeState(applicableWord);
            if (alternativeState.getAllowedSuccessors().equals(presentFlowAllowedSuccessors)) {
                return true;
            }
        }
        return false;
    }

    public List<TlsWord> getAllowedSuccessors() {
        ContextPropertyContainer propertyContainer = determineContextProperties();
        TlsWordType lastSentType = getEffectiveLastSent(propertyContainer);

        return stateMachine.getAlphabet().stream()
                .filter(
                        input ->
                                isAllowedSuccessor(
                                        lastSentType, input.getType(), propertyContainer))
                .collect(Collectors.toList());
    }

    public boolean reachedProperty(ContextProperty property) {
        ContextPropertyContainer propertyContainer = determineContextProperties();
        return propertyContainer.doPropertiesApply(property);
    }

    public Set<ContextProperty> getContextPropertiesReached() {
        ContextPropertyContainer propertyContainer = determineContextProperties();
        return propertyContainer.getActiveContextProperties();
    }

    /**
     * Determines if the given input must be accepted according to our input chains
     *
     * @param input possible next message
     * @return true if required, false if not required or not successor
     */
    public boolean isRequiredSuccessor(TlsWord input) {
        ContextPropertyContainer propertyContainer = determineContextProperties();
        TlsWordType lastSentType = getEffectiveLastSent(propertyContainer);
        return stateMachine.getAlphabet().stream()
                .filter(
                        letter ->
                                isRequiredSuccessor(
                                        lastSentType, letter.getType(), propertyContainer))
                .anyMatch(requiredInput -> requiredInput.equals(input));
    }

    /**
     * Determines if the given input is explicitly marked as optional successor
     *
     * @param input possible next message
     * @return true if optional, false if required or not allowed at all
     */
    public boolean isOptionalSuccessor(TlsWord input) {
        ContextPropertyContainer propertyContainer = determineContextProperties();
        TlsWordType lastSentType = getEffectiveLastSent(propertyContainer);
        return stateMachine.getAlphabet().stream()
                .filter(
                        letter ->
                                isOptionalSuccessor(
                                        lastSentType, letter.getType(), propertyContainer))
                .anyMatch(optionalInput -> optionalInput.equals(input));
    }

    private ContextPropertyContainer determineContextProperties() {
        ContextPropertyContainer propertyContainer = getContextPropertyContainer(stateMachine);
        getMessagesSent().forEach(propertyContainer::updateContextProperties);
        return propertyContainer;
    }

    public boolean isExpectedResponse(TlsWord input, SulResponse observedResponse) {
        ContextPropertyContainer propertyContainer = determineContextProperties();
        // determine context changes for possible new input
        propertyContainer.updateContextForSent(input);
        ExpectedResponse[] expectedResponses = getExpectedResponses(propertyContainer);

        // check if any expected response is applicable and matches
        return !Arrays.asList(expectedResponses).stream()
                .filter(
                        expectedResponse ->
                                expectedResponse.appliesTo(input.getType(), propertyContainer))
                .filter(
                        expectedResponse ->
                                expectedResponse.matchesObservedResponse(observedResponse))
                .collect(Collectors.toList())
                .isEmpty();
    }

    private TlsWordType getEffectiveLastSent(ContextPropertyContainer propertyContainer) {
        return getEffectiveLastSent(propertyContainer, messagesSent);
    }

    private TlsWordType getEffectiveLastSent(
            ContextPropertyContainer propertyContainer, List<TlsWord> messageStack) {
        // heartbeats should not limit our options if it does not lead to an error state
        List<TlsWord> nonHeartbeatSent =
                messageStack.stream()
                        .filter(
                                input ->
                                        !TlsWordType.effectivelyEquals(
                                                input.getType(), TlsWordType.HEARTBEAT))
                        .collect(Collectors.toList());
        TlsWordType lastSentType =
                (nonHeartbeatSent.isEmpty()
                        ? null
                        : nonHeartbeatSent.get(nonHeartbeatSent.size() - 1).getType());

        if (TlsWordType.effectivelyEquals(lastSentType, TlsWordType.ANY_CCS)) {
            if (propertyContainer.doPropertiesApply(ContextProperty.IS_TLS13_FLOW)
                    && propertyContainer.doPropertiesApply(ContextProperty.HANDSHAKE_UNFINISHED)) {
                // within a TLS 1.3 handshake, the CCS may loop
                // our options are limited by the last non-ccs
                return getLastInputNotMatchingType(nonHeartbeatSent, TlsWordType.ANY_CCS);
            } else if (propertyContainer.doPropertiesApply(ContextProperty.IS_TLS12_FLOW)
                    || !propertyContainer.doPropertiesApply(ContextProperty.HANDSHAKE_UNFINISHED)) {
                return lastSentType;
            } else {
                // we aren't commited to a version yet - we must still be at the start.
                // Since any sensible benign flow would define a version, we either
                // didn't send anything or a CCS
                if (lastSentType == TlsWordType.DUMMY_CCS) {
                    // a dummy CCS does not enable encryption on our end
                    // thus, we can continue as if nothing was sent
                    return null;
                } else {
                    // use the artificial dead end type to ensure no valid
                    // chain can be found
                    return TlsWordType.ARTIFICIAL_DEAD_END;
                }
            }
        }
        return getTargetSpecificEffectivelyLastSent(lastSentType, messagesSent, propertyContainer);
    }

    public TlsWordType getLastInputNotMatchingType(List<TlsWord> messageStack, TlsWordType type) {
        for (int i = messageStack.size() - 1; i >= 0; i--) {
            if (!TlsWordType.effectivelyEquals(messageStack.get(i).getType(), type)) {
                return messageStack.get(i).getType();
            }
        }
        return null;
    }

    public boolean isAllowedSuccessor(TlsWordType successor) {
        ContextPropertyContainer propertyContainer = determineContextProperties();
        return isAllowedSuccessor(
                getEffectiveLastSent(propertyContainer), successor, propertyContainer);
    }

    private boolean isAllowedSuccessor(
            TlsWordType predecessor,
            TlsWordType successor,
            ContextPropertyContainer propertyContainer) {
        LetterChain[] allowedLetterChains = getAllowedLetterChains(propertyContainer);
        return Arrays.asList(allowedLetterChains).stream()
                .anyMatch(
                        letterChain ->
                                letterChain.appliesTo(predecessor, successor, propertyContainer));
    }

    public boolean isRequiredSuccessor(TlsWordType successor) {
        ContextPropertyContainer propertyContainer = determineContextProperties();
        return isRequiredSuccessor(
                getEffectiveLastSent(propertyContainer), successor, propertyContainer);
    }

    private boolean isRequiredSuccessor(
            TlsWordType predecessor,
            TlsWordType successor,
            ContextPropertyContainer propertyContainer) {
        LetterChain[] allowedLetterChains = getAllowedLetterChains(propertyContainer);

        return Arrays.asList(allowedLetterChains).stream()
                .filter(LetterChain::isRequired)
                .anyMatch(
                        letterChain ->
                                letterChain.appliesTo(predecessor, successor, propertyContainer));
    }

    public boolean isOptionalSuccessor(TlsWordType successor) {
        ContextPropertyContainer propertyContainer = determineContextProperties();
        return isOptionalSuccessor(
                getEffectiveLastSent(propertyContainer), successor, propertyContainer);
    }

    private boolean isOptionalSuccessor(
            TlsWordType predecessor,
            TlsWordType successor,
            ContextPropertyContainer propertyContainer) {
        return isAllowedSuccessor(predecessor, successor, propertyContainer)
                && !isRequiredSuccessor(predecessor, successor, propertyContainer);
    }

    protected LetterChain[] getAllowedLetterChains(ContextPropertyContainer propertyContainer) {
        LetterChain[] allowedLetterChains;
        TlsLetterChainProvider tlsLetterChainProvider = getLetterChainProvider();
        if (propertyContainer.doPropertiesApply(ContextProperty.IS_TLS12_FLOW)) {
            allowedLetterChains = tlsLetterChainProvider.getAllowedTLS12LetterChains();
        } else if (propertyContainer.doPropertiesApply(ContextProperty.IS_TLS13_FLOW)) {
            allowedLetterChains = tlsLetterChainProvider.getAllowedTLS13LetterChains();
        } else {
            allowedLetterChains = tlsLetterChainProvider.getAllAllowedTLSLetterChains();
        }
        return allowedLetterChains;
    }

    protected ExpectedResponse[] getExpectedResponses(ContextPropertyContainer propertyContainer) {
        ExpectedResponse[] expectedResponses;
        ExpectedResponseProvider expectedResponseProvider = getExpectedResponseProvider();
        if (propertyContainer.doPropertiesApply(ContextProperty.IS_TLS12_FLOW)) {
            expectedResponses = expectedResponseProvider.getExpectedTls12Responses();
        } else if (propertyContainer.doPropertiesApply(ContextProperty.IS_TLS13_FLOW)) {
            expectedResponses = expectedResponseProvider.getExpectedTls13Responses();
        } else {
            expectedResponses = expectedResponseProvider.getAllExpectedResponses();
        }
        return expectedResponses;
    }

    protected abstract ContextPropertyContainer getContextPropertyContainer(
            StateMachine stateMachine);

    public List<TlsWord> getMessagesSent() {
        return messagesSent;
    }

    public Object getFinalStateReached() {
        List<Object> statesReachedSequence = getStatesReachedSequence();
        return statesReachedSequence.get(statesReachedSequence.size() - 1);
    }

    public List<Object> getStatesReachedSequence() {
        List<Object> statesReached = new LinkedList<>();
        Object state = stateMachine.getMealyMachine().getInitialState();
        statesReached.add(state);
        for (TlsWord input : messagesSent) {
            state = stateMachine.getMealyMachine().getSuccessor(state, input);
            statesReached.add(state);
        }
        return statesReached;
    }

    public TlsWordType getTargetSpecificEffectivelyLastSent(
            TlsWordType actualLastSent, List<TlsWord> messageStack) {
        ContextPropertyContainer propertyContainer = determineContextProperties();
        return getTargetSpecificEffectivelyLastSent(
                actualLastSent, messageStack, propertyContainer);
    }

    protected TlsWordType getTargetSpecificEffectivelyLastSent(
            TlsWordType actualLastSent,
            List<TlsWord> messageStack,
            ContextPropertyContainer propertyContainer) {
        return actualLastSent;
    }
}
