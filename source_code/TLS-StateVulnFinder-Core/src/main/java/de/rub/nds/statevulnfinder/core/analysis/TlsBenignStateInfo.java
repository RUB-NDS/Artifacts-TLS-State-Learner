/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.analysis;

import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextProperty;
import de.rub.nds.statevulnfinder.core.analysis.transitions.TransitionAnalyzer;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/** Contains information we assigned to a state throughout our analysis. */
public class TlsBenignStateInfo {
    private final Object state;
    // the names assigned to this state based on our traced subgraph
    private final Set<String> names;
    // list of inputs that may be used in this state as part of a valid message flow
    private final Set<TlsWord> benignInputs;
    // contains all inputs of **traversed** paths that lead to this state
    private final Set<TlsWordType> inputHistory;
    private final Set<ContextProperty> contextPropertiesWhenReached;

    private final Set<TlsWord> rejectedOptionalInputs;
    private final Set<TlsWord> rejectedExpectedInputs;

    public TlsBenignStateInfo(Object state) {
        this.state = state;
        names = new HashSet<>();
        benignInputs = new HashSet<>();
        contextPropertiesWhenReached = new HashSet<>();
        inputHistory = new HashSet<>();
        rejectedOptionalInputs = new HashSet<>();
        rejectedExpectedInputs = new HashSet<>();
    }

    public void addName(String name) {
        names.add(name);
    }

    public void addBenignInput(TlsWord newBenignInput) {
        getBenignInputs().add(newBenignInput);
    }

    public void addRejectedOptionalInput(TlsWord rejectedInput) {
        rejectedOptionalInputs.add(rejectedInput);
    }

    public void addRejectedExpectedInput(TlsWord rejectedInput) {
        rejectedExpectedInputs.add(rejectedInput);
    }

    public void updateTransitionInfo(TransitionAnalyzer transitionAnalyzer) {
        getContextPropertiesWhenReached().addAll(transitionAnalyzer.getContextPropertiesReached());
        getInputHistory()
                .addAll(
                        transitionAnalyzer.getMessagesSent().stream()
                                .map(TlsWord::getType)
                                .collect(Collectors.toList()));
    }

    public VersionFlow getVersionFlow() {
        if (contextPropertiesWhenReached.contains(ContextProperty.IS_TLS12_FLOW)
                && contextPropertiesWhenReached.contains(ContextProperty.IS_TLS13_FLOW)) {
            return VersionFlow.BOTH;
        } else if (contextPropertiesWhenReached.contains(ContextProperty.IS_TLS12_FLOW)) {
            return VersionFlow.TLS12;
        } else if (contextPropertiesWhenReached.contains(ContextProperty.IS_TLS13_FLOW)) {
            return VersionFlow.TLS13;
        }
        return VersionFlow.UNSPECIFIED;
    }

    public enum VersionFlow {
        TLS12,
        TLS13,
        BOTH,
        UNSPECIFIED
    }

    public Set<String> getNames() {
        return names;
    }

    public Object getState() {
        return state;
    }

    public Set<TlsWord> getBenignInputs() {
        return benignInputs;
    }

    public Set<TlsWord> getRejectedOptionalInputs() {
        return rejectedOptionalInputs;
    }

    public Set<TlsWord> getRejectedExpectedInputs() {
        return rejectedExpectedInputs;
    }

    /**
     * Determines if a given allowed input was rejected (i.e transitions to error state) in this
     * state
     *
     * @param input an allowed input
     * @return
     */
    public boolean isAllowedInputRejected(TlsWord input) {
        return rejectedOptionalInputs.contains(input) || rejectedExpectedInputs.contains(input);
    }

    public Set<ContextProperty> getContextPropertiesWhenReached() {
        return contextPropertiesWhenReached;
    }

    public boolean reachedProperty(ContextProperty property) {
        return contextPropertiesWhenReached.contains(property);
    }

    public boolean isPartOfRenegotiation() {
        return contextPropertiesWhenReached.contains(ContextProperty.ACCEPTED_RENEGOTIATION);
    }

    public Set<TlsWordType> getInputHistory() {
        return inputHistory;
    }
}
