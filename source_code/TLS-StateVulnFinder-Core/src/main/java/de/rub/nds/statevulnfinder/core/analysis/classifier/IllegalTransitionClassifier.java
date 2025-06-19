/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.analysis.classifier;

import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.analysis.TlsBenignStateInfo;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextProperty;
import de.rub.nds.statevulnfinder.core.analysis.transitions.TransitionAnalyzer;
import de.rub.nds.statevulnfinder.core.analysis.transitions.TransitionAnalyzerProvider;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.core.issue.CriticalMessageOutOfOrderIssue;
import de.rub.nds.statevulnfinder.core.issue.IgnoredInputIssue;
import de.rub.nds.statevulnfinder.core.issue.LeavingHappyFlowIssue;
import de.rub.nds.statevulnfinder.core.issue.OddErrorStateTransitionIssue;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import de.rub.nds.statevulnfinder.core.issue.UnwantedHappyFlowVulnerability;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.Stack;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class IllegalTransitionClassifier extends Classifier {

    private static final Logger LOG = LogManager.getLogger();
    private final TransitionAnalyzerProvider transitionAnalyzerProvider;
    private final GraphDetails graphDetails;

    public IllegalTransitionClassifier(
            GraphDetails graphDetails, TransitionAnalyzerProvider transitionAnalyzerProvider) {
        this.graphDetails = graphDetails;
        this.transitionAnalyzerProvider = transitionAnalyzerProvider;
    }

    /**
     * Determines all transitions from benign states that are unexpected and do not lead to a
     * determined error state.
     *
     * @param machine The learned StateMachine
     * @return the determined vulnerabilities
     */
    @Override
    public List<StateMachineIssue> getVulnerabilitiesOfClass(StateMachine machine) {
        determinedVulnerabilities = new LinkedList<>();
        HashMap<Object, TlsBenignStateInfo> stateInfoMap =
                getGraphDetails().getBenignStateInfoMap();
        Set<Object> reportedTransitions = new HashSet<>();
        if (stateInfoMap != null && !stateInfoMap.isEmpty()) {
            getIllegalReturningTransitions(
                    machine, stateInfoMap, determinedVulnerabilities, reportedTransitions);
            getIllegalLeavingTransitions(
                    machine, stateInfoMap, determinedVulnerabilities, reportedTransitions);
        } else {
            LOG.error(
                    "Benign subgraph for has not been identified - skipping IllegalTransitionClassifier");
        }

        return determinedVulnerabilities;
    }

    private void getIllegalLeavingTransitions(
            StateMachine machine,
            HashMap<Object, TlsBenignStateInfo> stateInfoMap,
            List<StateMachineIssue> determinedDeviations,
            Set<Object> reportedTransitions) {
        for (Object state : machine.getMealyMachine().getStates()) {
            // only look at states we can reach with benign flows
            if (stateInfoMap.containsKey(state)) {
                List<TlsWord> forbiddenInputs =
                        machine.getAlphabet().stream()
                                .filter(
                                        Predicate.not(
                                                stateInfoMap.get(state).getBenignInputs()
                                                        ::contains))
                                .collect(Collectors.toList());
                for (TlsWord input : forbiddenInputs) {
                    Object successor = machine.getMealyMachine().getSuccessor(state, input);
                    Object transition = machine.getMealyMachine().getTransition(state, input);
                    SulResponse output =
                            (SulResponse) machine.getMealyMachine().getOutput(state, input);
                    if (!reportedTransitions.contains(transition)) {
                        if (!successorIsErrorOrDummyState(successor)) {
                            reportLeavingDeviation(
                                    machine, state, successor, input, determinedDeviations);
                            reportedTransitions.add(transition);
                        } else if (shouldReportAsErrorTransitionWithUnexpectedResponse(
                                stateInfoMap, state, input, successor, output)) {
                            // report unexpected responses but only if it is not a rejected optional
                            // input as we track these already when building the benign subgraph
                            reportUnexpectedResponseTowardsErrorState(
                                    machine, state, output, input, determinedDeviations);
                            reportedTransitions.add(transition);
                        }
                    }
                }
            }
        }
    }

    private boolean shouldReportAsErrorTransitionWithUnexpectedResponse(
            HashMap<Object, TlsBenignStateInfo> stateInfoMap,
            Object state,
            TlsWord input,
            Object successor,
            SulResponse output) {
        if (stateInfoMap.get(state) != null
                && stateInfoMap
                        .get(state)
                        .getContextPropertiesWhenReached()
                        .contains(ContextProperty.HANDSHAKE_FINISHED_CORRECTLY)
                && TlsWordType.effectivelyEquals(TlsWordType.ANY_APP_DATA, input.getType())) {}
        return successorIsErrorOrDummyState(successor)
                && BenignSubgraphClassifier.responseToErrorStateIsUnexpected(output, input)
                && !stateInfoMap.get(state).isAllowedInputRejected(input);
    }

    private boolean successorIsErrorOrDummyState(Object successor) {
        return graphDetails.isErrorState(successor)
                || graphDetails.getIllegalTransitionLearnerState() == successor;
    }

    private void getIllegalReturningTransitions(
            StateMachine machine,
            HashMap<Object, TlsBenignStateInfo> stateInfoMap,
            List<StateMachineIssue> determinedDeviations,
            Set<Object> reportedTransitions) {
        // note that illegal inputs that loop within the state (e.g ignored inputs)
        // count as IllegalLeavingTransition
        for (Object state : machine.getMealyMachine().getStates()) {
            for (TlsWord input : machine.getAlphabet()) {
                Object successor = machine.getMealyMachine().getSuccessor(state, input);
                Object transition = machine.getMealyMachine().getTransition(state, input);
                if (stateInfoMap.containsKey(successor)
                        && !graphDetails.isErrorState(successor)
                        && !graphDetails.getHappyFlowsTransitions().contains(transition)
                        && state != successor
                        && !isPermittedReturn(input, state, successor, stateInfoMap)
                        && !reportedTransitions.contains(transition)) {
                    if (reportReturningDeviation(
                            machine, state, successor, input, determinedDeviations, transition)) {
                        reportedTransitions.add(transition);
                    }
                }
            }
        }
    }

    /**
     * Determines if the considered transition may return to a happy flow node. This is the case for
     * connection resets or close notifies. The latter may
     *
     * @return
     */
    private boolean isPermittedReturn(
            TlsWord input,
            Object state,
            Object successor,
            HashMap<Object, TlsBenignStateInfo> stateInfoMap) {
        if (input.getType() == TlsWordType.RESET_CONNECTION) {
            return true;
        } else if (input.getType() == TlsWordType.CLOSE_NOTIFY) {
            // close notify may lead us to a state which does not allow any further inputs (except
            // always permitted
            // ones)
            // we can't say for sure which state it is but it could be the dummy_ccs state or a BB
            // ccs state for example
            Set<TlsWordType> alwaysPermittedTypes =
                    new HashSet<>(
                            Arrays.asList(
                                    new TlsWordType[] {
                                        TlsWordType.RESET_CONNECTION,
                                        TlsWordType.HEARTBEAT,
                                        TlsWordType.CCS
                                    }));
            Set<TlsWord> permittedInputs = stateInfoMap.get(successor).getBenignInputs();
            return !permittedInputs.stream()
                    .map(TlsWord::getType)
                    .anyMatch(Predicate.not(alwaysPermittedTypes::contains));
        }
        return false;
    }

    private void reportLeavingDeviation(
            StateMachine machine,
            Object state,
            Object successorState,
            TlsWord input,
            List<StateMachineIssue> determinedDeviations) {
        List<TlsWord> path = getPath(machine, state, input);
        if (state == successorState) {
            determinedDeviations.add(
                    new IgnoredInputIssue(path, "Illegal input did not change the state"));
        } else {
            determinedDeviations.add(
                    new LeavingHappyFlowIssue(
                            path,
                            "This message sequence leaves the benign path without entering an error state"));
        }
    }

    private void reportUnexpectedResponseTowardsErrorState(
            StateMachine machine,
            Object state,
            SulResponse output,
            TlsWord input,
            List<StateMachineIssue> determinedDeviations) {
        List<TlsWord> path = getPath(machine, state, input);
        determinedDeviations.add(
                new OddErrorStateTransitionIssue(
                        path,
                        output.getResponseFingerprint(),
                        "Illegal input leads to error state but with unexpected response"));
    }

    private boolean reportReturningDeviation(
            StateMachine machine,
            Object state,
            Object successorState,
            TlsWord input,
            List<StateMachineIssue> determinedDeviations,
            Object transition) {
        List<TlsWord> initialPath = getPath(machine, state, input);
        List<TlsWord> finPath = getFinishedPath(machine, successorState);
        boolean foundConfirmingPath = true;
        if (finPath.isEmpty() && !graphDetails.getFinStates().contains(successorState)) {
            foundConfirmingPath = false;
        }
        initialPath.addAll(finPath);
        Stack<TlsWord> messageStack = new Stack<>();
        messageStack.addAll(initialPath);
        TransitionAnalyzer transitionAnalyzer =
                transitionAnalyzerProvider.getTransitionAnalyzer(messageStack, machine);
        if (!transitionAnalyzer.isEffectivelyBenignFlow()) {
            // there may always be returning edges if a reset was used followed
            // by a proper happy flow - we filter these here
            initialPath = reducePathIfPossible(initialPath, machine, transition);
            determinedDeviations.add(
                    new UnwantedHappyFlowVulnerability(
                            new ArrayList<>(initialPath), foundConfirmingPath));
            return true;
        }
        return false;
    }

    private List<TlsWord> getPath(StateMachine machine, Object state, TlsWord input) {
        List<TlsWord> path;
        path = getPathToNodeResetting(machine, machine.getMealyMachine().getInitialState(), state);
        if (path.isEmpty() && state != machine.getMealyMachine().getInitialState()) {
            LOG.error("Was unable to find a path to sought state. Using empty path.");
        }
        path.add(input);
        return path;
    }

    private List<TlsWord> getFinishedPath(StateMachine machine, Object benignStateReached) {
        List<TlsWord> path = new LinkedList<>();
        if (!getGraphDetails().getFinStates().isEmpty()) {
            path =
                    getPathToNodeResetting(
                            machine,
                            benignStateReached,
                            getGraphDetails().getFinStates().toArray());
        }
        return path;
    }

    private void reportCriticalOutOfOrderTransitions(
            StateMachine machine,
            List<StateMachineIssue> determinedDeviations,
            Set<Object> reportedTransitions,
            List<Object> criticalTransitions) {
        for (Object state : machine.getMealyMachine().getStates()) {
            for (TlsWord input : machine.getAlphabet()) {
                Object transition = machine.getMealyMachine().getTransition(state, input);
                SulResponse output =
                        (SulResponse) machine.getMealyMachine().getOutput(state, input);
                if (!graphDetails.getHappyFlowsTransitions().contains(transition)
                        && !reportedTransitions.contains(transition)) {
                    if (output.responseContainsMessage(FinishedMessage.class)) {
                        determinedDeviations.add(
                                new CriticalMessageOutOfOrderIssue(
                                        getPath(machine, state, input),
                                        "Received Finished message outside of a happy flow"));
                        criticalTransitions.add(transition);
                    } else if (output.responseContainsMessage(ChangeCipherSpecMessage.class)) {
                        determinedDeviations.add(
                                new CriticalMessageOutOfOrderIssue(
                                        getPath(machine, state, input),
                                        "Received ChangeCipherSpec message outside of a happy flow"));
                        criticalTransitions.add(transition);
                    }
                }
            }
        }
        graphDetails.getHappyFlowsTransitions();
    }

    protected GraphDetails getGraphDetails() {
        return graphDetails;
    }
}
