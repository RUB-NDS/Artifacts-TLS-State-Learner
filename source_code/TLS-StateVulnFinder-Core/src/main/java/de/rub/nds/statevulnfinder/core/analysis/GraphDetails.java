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
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.core.issue.DivergingBleichenbacherVulnerability;
import de.rub.nds.statevulnfinder.core.issue.DivergingPaddingOracleVulnerability;
import de.rub.nds.statevulnfinder.core.issue.SameStateBleichenbacherVulnerability;
import de.rub.nds.statevulnfinder.core.issue.SameStatePaddingOracleVulnerability;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import java.util.*;
import java.util.stream.Collectors;
import net.automatalib.automata.transducers.MealyMachine;

public class GraphDetails {

    private Set<Object> errorStates;
    private Set<Object> redundantBenignStates;

    // collects all information gathered for expected states (except error states)
    private HashMap<Object, TlsBenignStateInfo> benignStateInfoMap;

    private Object initialState;

    private Object illegalLearnerTransitionState;

    private Set<Object> happyFlowsTransitions;
    private Set<Object> criticalOutputTransitions;

    private Set<Object> divergingBleichenbacherStates;

    // list of vulnerabilities found by the classifiers, also contains PaddingOracle and
    // Bleichenbacher vunerabilities
    List<StateMachineIssue> vulnList = new LinkedList<>();

    public Map<String, String> getNodeNames() {
        Map<String, String> collectedNodeNames = new HashMap<>();
        if (benignStateInfoMap != null) {
            // todo: do we want shorter names?
            for (Object state : benignStateInfoMap.keySet()) {
                List<String> names = new LinkedList<>(benignStateInfoMap.get(state).getNames());
                Collections.sort(names);
                collectedNodeNames.put(
                        state.toString(), names.stream().collect(Collectors.joining("-")));
            }
            for (Object state : errorStates) {
                if (illegalLearnerTransitionState == state && errorStates.size() > 1) {
                    collectedNodeNames.put(state.toString(), "Dummy");
                } else {
                    collectedNodeNames.put(state.toString(), "Error");
                }
            }
            return collectedNodeNames;
        }
        return collectedNodeNames;
    }

    public Object getInitialState() {
        return initialState;
    }

    public void setInitialState(Object initialState) {
        this.initialState = initialState;
    }

    public Set<Object> getFinStates() {
        if (benignStateInfoMap != null) {
            return benignStateInfoMap.keySet().stream()
                    .filter(
                            state ->
                                    benignStateInfoMap
                                            .get(state)
                                            .getNames()
                                            .contains(TlsWordType.FINISHED.name()))
                    .collect(Collectors.toSet());
        }
        return new HashSet<>();
    }

    public Set<Object> getHappyFlowsTransitions() {
        return happyFlowsTransitions;
    }

    public void setHappyFlowsTransitions(Set<Object> happyFlowsTransitions) {
        this.happyFlowsTransitions = happyFlowsTransitions;
    }

    public List<StateMachineIssue> getVulnList() {
        return vulnList;
    }

    public List<StateMachineIssue> getVulnListOnlyBBAndPO() {
        return vulnList.stream()
                .filter(
                        vuln ->
                                (vuln instanceof DivergingBleichenbacherVulnerability
                                        || vuln instanceof DivergingPaddingOracleVulnerability
                                        || vuln instanceof SameStateBleichenbacherVulnerability
                                        || vuln instanceof SameStatePaddingOracleVulnerability))
                .collect(Collectors.toList());
    }

    public List<StateMachineIssue> getVulnListWithoutBBAndPO() {
        return vulnList.stream()
                .filter(
                        vuln ->
                                !(vuln instanceof DivergingBleichenbacherVulnerability
                                        || vuln instanceof DivergingPaddingOracleVulnerability
                                        || vuln instanceof SameStateBleichenbacherVulnerability
                                        || vuln instanceof SameStatePaddingOracleVulnerability))
                .collect(Collectors.toList());
    }

    public Set<Object> getTopVulnerabilityPath(MealyMachine mealyMachine) {
        List<StateMachineIssue> vulnList = new LinkedList<>(getVulnListWithoutBBAndPO());
        Set<Object> edges = new HashSet<>();
        if (vulnList.isEmpty()) {
            return edges;
        }
        vulnList.sort(Comparator.comparing(StateMachineIssue::getType));
        // get the most dire vulnerability
        StateMachineIssue vulnerability = vulnList.get(0);
        // walk through the state machine and collect the edges we see during the vulnerability
        Object state = mealyMachine.getInitialState();
        for (TlsWord tlsWord : vulnerability.getPath()) {
            edges.add(mealyMachine.getTransition(state, tlsWord));
            state = mealyMachine.getSuccessor(state, tlsWord);
        }
        return edges;
    }

    public void setVulnList(List<StateMachineIssue> vulnList) {
        this.vulnList = vulnList;
    }

    public Object getIllegalTransitionLearnerState() {
        return illegalLearnerTransitionState;
    }

    public void setIllegalTransitionLearnerState(Object illegalTransitionLearnerState) {
        this.illegalLearnerTransitionState = illegalTransitionLearnerState;
    }

    public Set<Object> getDivergingBleichenbacherStates() {
        return divergingBleichenbacherStates;
    }

    public void setDivergingBleichenbacherStates(Set<Object> divergingBleichenbacherStates) {
        this.divergingBleichenbacherStates = divergingBleichenbacherStates;
    }

    public Set<Object> getErrorStates() {
        return errorStates;
    }

    public void setErrorStates(Set<Object> errorStates) {
        this.errorStates = errorStates;
    }

    public boolean isErrorState(Object state) {
        if (errorStates != null) {
            return errorStates.contains(state);
        }
        return false;
    }

    public HashMap<Object, TlsBenignStateInfo> getBenignStateInfoMap() {
        return benignStateInfoMap;
    }

    public void setBenignStateInfoMap(HashMap<Object, TlsBenignStateInfo> benignStateInfoMap) {
        this.benignStateInfoMap = benignStateInfoMap;
    }

    public void mergeStateInfo(Object state) {
        if (!benignStateInfoMap.containsKey(state)) {
            benignStateInfoMap.put(state, new TlsBenignStateInfo(state));
        }
    }

    public TlsBenignStateInfo getStateInfo(Object state) {
        if (benignStateInfoMap == null || !benignStateInfoMap.containsKey(state)) {
            return null;
        }
        return benignStateInfoMap.get(state);
    }

    public boolean hasStateInfo(Object state) {
        return getStateInfo(state) != null;
    }

    public Set<Object> getRedundantBenignStates() {
        return redundantBenignStates;
    }

    public void setRedundantBenignStates(Set<Object> redundantBenignStates) {
        this.redundantBenignStates = redundantBenignStates;
    }

    public void setCriticalOutputTransitions(Set<Object> criticalOutputTransitions) {
        this.criticalOutputTransitions = criticalOutputTransitions;
    }

    public Set<Object> getCriticalOutputTransitions() {
        return criticalOutputTransitions;
    }
}
