/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.analysis.transitions;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public enum ContextProperty {
    OFFERED_SESSION_TICKET_EXTENSION(Lifetime.IN_HANDSHAKE),
    RECEIVED_TICKET(Lifetime.ESTABLISHED),
    RECEIVED_SESSION_ID(Lifetime.ESTABLISHED),
    CAN_RESUME_CORRECTLY_TLS12(Lifetime.CROSS_CONNECTION),
    CAN_RESUME_CORRECTLY_TLS13(Lifetime.CROSS_CONNECTION),
    IN_RESUMPTION_FLOW(Lifetime.IN_HANDSHAKE),
    CLIENT_AUTH_REQUESTED(Lifetime.IN_HANDSHAKE),
    BLEICHENBACHER_PATH(Lifetime.CONNECTION), // BB should alwas poison the flow
    EARLY_HEARTBEAT_SENT(Lifetime.IN_HANDSHAKE),
    HANDSHAKE_UNFINISHED(Lifetime.IN_HANDSHAKE),
    HANDSHAKE_FINISHED_CORRECTLY(Lifetime.ESTABLISHED),
    IS_TLS13_FLOW(Lifetime.CONNECTION),
    FINISHED_SENT(Lifetime.IN_HANDSHAKE),
    FINISHED_RECEIVED(Lifetime.IN_HANDSHAKE),
    IS_TLS12_FLOW(Lifetime.CONNECTION),
    IS_EPHEMERAL_HANDSHAKE(Lifetime.IN_HANDSHAKE),
    REJECTED_RENEGOTIATION(Lifetime.ESTABLISHED),
    ACCEPTED_RENEGOTIATION(Lifetime.IN_HANDSHAKE),
    CLIENT_LEARNER_SERVER_HELLO_SENT(Lifetime.IN_HANDSHAKE),
    CCS_SENT(Lifetime.ESTABLISHED),

    // negating properties are never actually set - they count as active
    // if their counterpart is not set
    NOT_IN_RESUMPTION_FLOW(Lifetime.IN_HANDSHAKE),
    NOT_CLIENT_AUTH_REQUESTED(Lifetime.IN_HANDSHAKE),
    NOT_IS_EPHEMERAL_HANDSHAKE(Lifetime.IN_HANDSHAKE),
    NOT_BLEICHENBACHER_PATH(Lifetime.CONNECTION),
    NOT_CLIENT_LEARNER_SERVER_HELLO_SENT(Lifetime.IN_HANDSHAKE),
    NOT_FINISHED_SENT(Lifetime.IN_HANDSHAKE),
    NOT_OFFERED_SESSION_TICKET_EXTENSION(Lifetime.IN_HANDSHAKE),
    NOT_IS_TLS12_FLOW(Lifetime.CONNECTION),
    NOT_IS_TLS13_FLOW(Lifetime.CONNECTION);

    // defines properties that must remain set even upon a connection reset
    private final Lifetime propertyLifetime;

    private ContextProperty(Lifetime propertyLifetime) {
        this.propertyLifetime = propertyLifetime;
    }

    public Lifetime getPropertyLifetime() {
        return propertyLifetime;
    }

    public static boolean contextPropertiesMatch(
            Set<ContextProperty> setA, Set<ContextProperty> setB) {
        // get disjoint elements
        Set<ContextProperty> conflictCandidates = new HashSet<>(setA);
        conflictCandidates.addAll(setB);

        Set<ContextProperty> intersection = new HashSet<>(setA);
        intersection.retainAll(setB);
        conflictCandidates.removeAll(intersection);

        for (ContextProperty property : conflictCandidates) {
            try {
                if (property == IS_EPHEMERAL_HANDSHAKE) {
                    // ephemeral / static cipher suite is not a conflict as the difference in server
                    // behavior is only visible when sending the CH that sets this property
                    continue;
                } else if (property == IN_RESUMPTION_FLOW
                        && setA.contains(ContextProperty.IS_TLS13_FLOW)
                        && setB.contains(ContextProperty.IS_TLS13_FLOW)) {
                    continue; // Resumption has no difference in TLS 1.3 if client auth is disabled
                }
                property.getNegatingProperty();
                return false;
            } catch (IllegalArgumentException e) {
                // if the property is not a negating property, we can ignore it
            }
        }
        return true;
    }

    public static Set<ContextProperty> stripPermittedContextDifferences(
            Set<ContextProperty> givenProperties) {
        Set<ContextProperty> strippedProperties = new HashSet<>(givenProperties);
        strippedProperties.remove(ContextProperty.EARLY_HEARTBEAT_SENT);
        return strippedProperties;
    }

    public enum Lifetime {
        // only during handshake relevant
        IN_HANDSHAKE,
        // relevant until the next handshake starts
        ESTABLISHED,
        // properties that remain active during renegotiation (e.g IS_TLS12_FLOW)
        CONNECTION,
        // properties that remain active after a reset (e.g CAN_RESUME)
        CROSS_CONNECTION
    }

    public boolean isEstablishedProperty() {
        return this.getPropertyLifetime() == Lifetime.ESTABLISHED;
    }

    public boolean isInHandshakeProperty() {
        return this.getPropertyLifetime() == Lifetime.IN_HANDSHAKE;
    }

    public boolean isCrossConnectionProperty() {
        return this.getPropertyLifetime() == Lifetime.CROSS_CONNECTION;
    }

    public boolean isNegatingProperty() {
        return this.name().startsWith("NOT_");
    }

    /**
     * Returns the property this ContextProperty negates
     *
     * @return the negated property
     */
    public ContextProperty getNegatedProperty() {
        if (isNegatingProperty()) {
            return ContextProperty.valueOf(this.name().replace("NOT_", ""));
        }
        return null;
    }

    public ContextProperty getNegatingProperty() {
        if (isNegatingProperty()) {
            throw new IllegalArgumentException("This element is already a negating property");
        }
        return ContextProperty.valueOf("NOT_" + this.name());
    }

    /**
     * Filters negating properties from a given array.
     *
     * @param propertyList An array that may contain negating properties
     * @return the array that only contains non-negating properties
     */
    public static ContextProperty[] filterNegatingProperties(ContextProperty[] propertyList) {
        List<ContextProperty> remainingProperties = new LinkedList<>();
        for (ContextProperty property : propertyList) {
            if (!property.isNegatingProperty()) {
                remainingProperties.add(property);
            }
        }
        return remainingProperties.toArray(new ContextProperty[0]);
    }
}
