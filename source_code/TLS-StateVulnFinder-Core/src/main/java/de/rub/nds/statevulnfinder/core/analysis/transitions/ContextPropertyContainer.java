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
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/** */
public abstract class ContextPropertyContainer {
    private Set<ContextProperty> activeContextProperties = new HashSet<>();
    protected Object lastState = null;
    protected final StateMachine stateMachine;

    public ContextPropertyContainer(StateMachine stateMachine) {
        this.stateMachine = stateMachine;
        activeContextProperties.add(ContextProperty.HANDSHAKE_UNFINISHED);
        lastState = stateMachine.getMealyMachine().getInitialState();
    }

    public void updateContextProperties(TlsWord concreteMessageSent) {
        if (concreteMessageSent == null) {
            throw new IllegalArgumentException("Invalid input null for context update");
        }

        updateContextForSent(concreteMessageSent);
        updateContextForResponse(concreteMessageSent);
        updateLastState(concreteMessageSent);
    }

    public abstract void updateContextForSent(TlsWord concreteMessageSent);

    protected abstract void updateContextForResponse(TlsWord concreteMessageSent);

    public boolean doPropertiesApply(ContextProperty... properties) {
        for (ContextProperty property : properties) {
            if (property.isNegatingProperty()
                    && activeContextProperties.contains(property.getNegatedProperty())) {
                return false;
            } else if (!property.isNegatingProperty()
                    && !activeContextProperties.contains(property)) {
                return false;
            }
        }
        return true;
    }

    public void setContextProperties(ContextProperty... newContextProperties) {
        for (ContextProperty property : newContextProperties) {
            if (property.isNegatingProperty()) {
                activeContextProperties.remove(property.getNegatedProperty());
            } else {
                activeContextProperties.add(property);
            }
        }
    }

    public void removeContextProperties(ContextProperty... propertiesToRemove) {
        for (ContextProperty property : propertiesToRemove) {
            if (property.isNegatingProperty()) {
                throw new IllegalArgumentException(
                        "Removing negating property  " + property + " has no effect");
            }
        }
        activeContextProperties.removeAll(Arrays.asList(propertiesToRemove));
    }

    public Set<ContextProperty> getActiveContextProperties() {
        return Collections.unmodifiableSet(activeContextProperties);
    }

    public void setActiveContextProperties(Set<ContextProperty> activeContextProperties) {
        this.activeContextProperties = activeContextProperties;
    }

    protected List<ProtocolMessage> queryStateMachine(TlsWord concreteMessageSent) {
        SulResponse sulResponse =
                (SulResponse)
                        stateMachine.getMealyMachine().getOutput(lastState, concreteMessageSent);

        List<ProtocolMessage> receivedMessages =
                sulResponse.getResponseFingerprint().getMessageList();
        return (receivedMessages == null) ? new ArrayList<>() : receivedMessages;
    }

    protected void updateLastState(TlsWord concreteMessageSent) {
        lastState = stateMachine.getMealyMachine().getSuccessor(lastState, concreteMessageSent);
    }

    protected void checkForReceivedFinished(List<ProtocolMessage> responses) {
        if (responses.stream().anyMatch(FinishedMessage.class::isInstance)) {
            setContextProperties(ContextProperty.FINISHED_RECEIVED);
        }
    }

    protected void checkForFinishedHandshake() {
        if (doPropertiesApply(ContextProperty.FINISHED_RECEIVED, ContextProperty.FINISHED_SENT)
                && !doPropertiesApply(ContextProperty.BLEICHENBACHER_PATH)) {
            dropInHandshakeLifetimeProperties();
            removeContextProperties(ContextProperty.HANDSHAKE_UNFINISHED);
            setContextProperties(ContextProperty.HANDSHAKE_FINISHED_CORRECTLY);
        }
    }

    /** Drops all properties tied to the most recent handshake */
    protected void handshakeStartedPropertyUpdate() {
        dropInHandshakeLifetimeProperties();
        dropEstablishedLifetimeProperties();
        setContextProperties(ContextProperty.HANDSHAKE_UNFINISHED);
    }

    protected void dropInHandshakeLifetimeProperties() {
        setActiveContextProperties(
                getActiveContextProperties().stream()
                        .filter(Predicate.not(ContextProperty::isInHandshakeProperty))
                        .collect(Collectors.toSet()));
    }

    protected void dropEstablishedLifetimeProperties() {
        setActiveContextProperties(
                getActiveContextProperties().stream()
                        .filter(Predicate.not(ContextProperty::isEstablishedProperty))
                        .collect(Collectors.toSet()));
    }

    /** Drops all properties that are irrelevant after a connection reset */
    protected void connectionResetPropertyUpdate() {
        setActiveContextProperties(
                getActiveContextProperties().stream()
                        .filter(ContextProperty::isCrossConnectionProperty)
                        .collect(Collectors.toSet()));
        setContextProperties(ContextProperty.HANDSHAKE_UNFINISHED);
    }
}
