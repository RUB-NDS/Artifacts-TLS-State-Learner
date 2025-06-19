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
import de.rub.nds.statevulnfinder.core.algorithm.words.ResetConnectionWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextProperty;
import de.rub.nds.statevulnfinder.core.analysis.transitions.TransitionAnalyzer;
import de.rub.nds.statevulnfinder.core.analysis.transitions.TransitionAnalyzerProvider;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.core.issue.NoHappyFlowIssue;
import de.rub.nds.statevulnfinder.core.issue.OddErrorStateTransitionIssue;
import de.rub.nds.statevulnfinder.core.issue.RedundantBenignStateIssue;
import de.rub.nds.statevulnfinder.core.issue.StateConfusionIssue;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
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

public class BenignSubgraphClassifier extends Classifier {

    public static final String START_NODE_NAME = "Start";

    private static final Logger LOG = LogManager.getLogger();

    private final GraphDetails graphDetails;
    // the inputs that may be sent from this state
    private HashMap<Object, Set<TlsWord>> stateInputMap;
    private HashMap<Object, Set<TlsWord>> stateRejectedOptionalInputMap;
    private HashMap<Object, Set<String>> stateNameMap;
    private Set<Object> coveredTransitions;
    private Set<Object> reportedTransitions;
    private final TransitionAnalyzerProvider transitionAnalyzerProvider;
    private Object initialState;

    public BenignSubgraphClassifier(
            GraphDetails graphDetails, TransitionAnalyzerProvider transitionAnalyzerProvider) {
        this.graphDetails = graphDetails;
        this.transitionAnalyzerProvider = transitionAnalyzerProvider;
    }

    @Override
    public List<StateMachineIssue> getVulnerabilitiesOfClass(StateMachine machine) {
        stateInputMap = new HashMap<>();
        stateNameMap = new HashMap<>();
        reportedTransitions = new HashSet<>();
        List<StateMachineIssue> determinedQuirks = new LinkedList<>();
        graphDetails.setHappyFlowsTransitions(new HashSet<>());
        graphDetails.setBenignStateInfoMap(new HashMap<>());
        graphDetails.setRedundantBenignStates(new HashSet<>());
        getBenignSubgraph(machine, determinedQuirks, false);
        if (machine.getAlphabet().containsSymbol(new ResetConnectionWord())) {
            // trace again and only now allow connection resets
            // this way, we first report as many transitions as possible without using resets in the
            // sequence
            getBenignSubgraph(machine, determinedQuirks, true);
        }
        return determinedQuirks;
    }

    private void checkConflictingContextProperties(
            Object state,
            Set<ContextProperty> reachedProperties,
            List<StateMachineIssue> determinedQuirks) {
        if (!graphDetails.getStateInfo(state).getContextPropertiesWhenReached().isEmpty()
                && !graphDetails.getStateInfo(state).getNames().contains("DUMMY_CCS")) {
            Set<ContextProperty> propertiesRegisteredForState =
                    new HashSet<>(
                            graphDetails.getStateInfo(state).getContextPropertiesWhenReached());
            if (!ContextProperty.contextPropertiesMatch(
                    propertiesRegisteredForState, reachedProperties)) {
                determinedQuirks.add(
                        new StateConfusionIssue(
                                new LinkedList<>(),
                                "State "
                                        + state
                                        + " has conflicting context properties "
                                        + graphDetails
                                                .getStateInfo(state)
                                                .getContextPropertiesWhenReached()
                                        + " and "
                                        + reachedProperties));
            }
        }
    }

    private void getBenignSubgraph(
            StateMachine machine,
            List<StateMachineIssue> determinedQuirks,
            boolean allowResetConnection) {
        coveredTransitions = new HashSet<>();
        initialState = machine.getMealyMachine().getInitialState();
        Stack<TlsWord> messageStack = new Stack<>();
        stateNameMap.put(initialState, new HashSet<>(Arrays.asList(START_NODE_NAME)));
        findBenignSubgraph(
                machine, initialState, messageStack, determinedQuirks, allowResetConnection);
    }

    /**
     * Iterates over the state machine using benign input sequences. It determines if any benign
     * transitions lead to an error state or if the transitions between states are unexpected. It
     * also determines all benign states and inputs that may be used in a benign flow when in these
     * states.
     *
     * @param machine StateMachine that will be analyzed.
     * @param state Current state in the depth first search algorithm.
     * @param vulnList List in which all found invalid happy Flows will be reported
     * @param messageStack A variable which holds the current path in the state machine
     * @param allowResetConnection Determines if subgraph tracing may leave an error state via
     *     connection reset
     */
    private void findBenignSubgraph(
            StateMachine machine,
            Object state,
            Stack<TlsWord> messageStack,
            List<StateMachineIssue> determinedQuirks,
            boolean allowResetConnection) {
        TransitionAnalyzer transitionAnalyzer =
                transitionAnalyzerProvider.getTransitionAnalyzer(messageStack, machine);
        List<TlsWord> allowedTransitions = new LinkedList<>();
        graphDetails.mergeStateInfo(state);
        if (!graphDetails.isErrorState(state)) {
            nameState(messageStack, state, determinedQuirks, transitionAnalyzer);
            allowedTransitions = transitionAnalyzer.getAllowedSuccessors();
            checkConflictingContextProperties(
                    state, transitionAnalyzer.getContextPropertiesReached(), determinedQuirks);
            graphDetails.getStateInfo(state).updateTransitionInfo(transitionAnalyzer);
        } else if (allowResetConnection) {
            // we keep tracing the subgraph when reaching an error state
            // if we can send a ResetConnectionWord - this allows us to cover
            // possible duplicated benign transitions caused by a learner artifact
            allowedTransitions = new LinkedList(Arrays.asList(new ResetConnectionWord()));
        }

        // iteratively call on all neighbors reachable with allowed words
        for (TlsWord nextInput : allowedTransitions) {
            SulResponse output =
                    (SulResponse) machine.getMealyMachine().getOutput(state, nextInput);
            if (output.isIllegalTransitionFlag()) {
                // transitions may be blocked by IllegalLearnerTransitions
                continue;
            }

            Object nextState = machine.getMealyMachine().getSuccessor(state, nextInput);
            Object transition = machine.getMealyMachine().getTransition(state, nextInput);
            checkSuccessorStateRedundancy(
                    state,
                    nextState,
                    nextInput,
                    allowedTransitions,
                    messageStack,
                    machine,
                    determinedQuirks);
            boolean newTransition =
                    processTransition(machine, state, nextState, nextInput, transition);

            evaluateTransition(
                    state,
                    transition,
                    nextInput,
                    nextState,
                    output,
                    transitionAnalyzer,
                    determinedQuirks,
                    messageStack,
                    machine);

            if (newTransition
                    && !isTls13LegacyCcsLoop(state, nextState, transitionAnalyzer, nextInput)) {
                // only look a nodes we have not reached with this transition yet
                findBenignSubgraph(
                        machine, nextState, messageStack, determinedQuirks, allowResetConnection);
            }
            messageStack.pop();
        }
    }

    /**
     * @param state the last state we evaluated
     * @param nextState the state reached by sending nextInput
     * @param transitionAnalyzer the analyzer for our current flow
     * @param nextInput the input in question
     * @return true if input looped and TLS 1.3 flow or at start
     */
    private boolean isTls13LegacyCcsLoop(
            Object state,
            Object nextState,
            TransitionAnalyzer transitionAnalyzer,
            TlsWord nextInput) {
        if (state != nextState
                || !TlsWordType.effectivelyEquals(nextInput.getType(), TlsWordType.ANY_CCS)) {
            return false;
        }
        return state == initialState
                || transitionAnalyzer.reachedProperty(ContextProperty.IS_TLS13_FLOW);
    }

    private void evaluateTransition(
            Object state,
            Object transition,
            TlsWord input,
            Object nextState,
            SulResponse output,
            TransitionAnalyzer transitionAnalyzer,
            List<StateMachineIssue> determinedQuirks,
            Stack<TlsWord> messageStack,
            StateMachine machine) {
        messageStack.add(input);
        List<TlsWord> messagesSent = new LinkedList<>(messageStack);
        if (!reportedTransitions.contains(transition)) {
            if (graphDetails.isErrorState(nextState)) {
                if (transitionAnalyzer.isRequiredSuccessor(input)) {
                    messagesSent = reducePathIfPossible(messagesSent, machine, transition);
                    determinedQuirks.add(
                            new NoHappyFlowIssue(
                                    output.getResponseFingerprint(),
                                    "Benign transition led to error state",
                                    messagesSent));
                    reportedTransitions.add(transition);
                    graphDetails.getStateInfo(state).addRejectedExpectedInput(input);
                } else if (transitionAnalyzer.isOptionalSuccessor(input)
                        && responseToErrorStateIsUnexpected(output, input)) {
                    messagesSent = reducePathIfPossible(messagesSent, machine, transition);
                    determinedQuirks.add(
                            new OddErrorStateTransitionIssue(
                                    messagesSent,
                                    output.getResponseFingerprint(),
                                    "Optional input leads to error state but response is unexpected"));
                    reportedTransitions.add(transition);
                    graphDetails.getStateInfo(state).addRejectedOptionalInput(input);
                }
            } else {
                if (!transitionAnalyzer.isExpectedResponse(input, output)) {
                    // report wrong response but continue analysis
                    messagesSent = reducePathIfPossible(messagesSent, machine, transition);
                    determinedQuirks.add(
                            new NoHappyFlowIssue(
                                    output.getResponseFingerprint(),
                                    "Unexpected output for " + input,
                                    messagesSent));
                    reportedTransitions.add(transition);
                }
            }
        }
    }

    private boolean processTransition(
            StateMachine machine,
            Object state,
            Object nextState,
            TlsWord input,
            Object transition) {
        boolean newTransition = !coveredTransitions.contains(transition);
        coveredTransitions.add(transition);
        if (!graphDetails.isErrorState(nextState)) {
            addTransitionToState(state, input, transition);
        }
        return newTransition;
    }

    private void nameState(
            Stack<TlsWord> messageStack,
            Object state,
            List<StateMachineIssue> determinedQuirks,
            TransitionAnalyzer transitionAnalyzer) {
        if (!messageStack.isEmpty()) {
            if (!stateNameMap.containsKey(state)) {
                stateNameMap.put(state, new HashSet<>());
            }
            Set<String> knownNames = stateNameMap.get(state);
            TlsWordType lastSentType = messageStack.get(messageStack.size() - 1).getType();

            if (!knownNames.contains(lastSentType.name())) {
                if (!isBenignRename(knownNames, lastSentType, transitionAnalyzer)) {
                    determinedQuirks.add(
                            new StateConfusionIssue(
                                    new ArrayList<>(messageStack),
                                    "State "
                                            + state
                                            + " is already known as "
                                            + stateNameMap.get(state)
                                            + " applying unexpected name "
                                            + lastSentType));
                }
                knownNames.add(lastSentType.name());
                graphDetails.getStateInfo(state).addName(lastSentType.name());
            }
        }
    }

    private boolean isBenignRename(
            Set<String> knownNames,
            TlsWordType lastSentType,
            TransitionAnalyzer transitionAnalyzer) {

        if (knownNames.isEmpty() || lastSentType == TlsWordType.RESET_CONNECTION) {
            return true;
        }

        Set<TlsWordType> stateReachingTypes =
                knownNames.stream()
                        .filter(Predicate.not(START_NODE_NAME::equals))
                        .map(TlsWordType::valueOf)
                        .collect(Collectors.toSet());

        // input causes a loop and thus may rename state
        boolean isLoopingInput = transitionAnalyzer.lastInputMayLoop();
        boolean appDataOverlapsRenegotiation =
                TlsWordType.effectivelyEquals(lastSentType, TlsWordType.ANY_APP_DATA)
                        && transitionAnalyzer.getTargetSpecificEffectivelyLastSent(
                                        lastSentType, transitionAnalyzer.getMessagesSent())
                                == TlsWordType.HELLO_REQUEST;

        // another input that allows the same successors leads to this state
        // e.g a TLS 1.3 resuming CH vs regular CH
        boolean successorsMatch = true;
        for (TlsWordType type : stateReachingTypes) {
            if (!transitionAnalyzer.yieldsEqualSuccessorsAsLast(type)) {
                successorsMatch = false;
            }
        }

        return isLoopingInput || successorsMatch || appDataOverlapsRenegotiation;
    }

    /**
     * Reports if a state is benign but redundant. This check is based on the allowed successors of
     * an input. If two inputs have the same successor inputs but lead to different subsequent
     * states, we consider one of these states redundant.
     *
     * @param currentState The state we are currently leaving
     * @param successorState The state we are entering next
     * @param input The input that lead to the new state
     * @param allowedInputs The list of allowed inputs from the state we are leaving
     * @param messageStack The messages we sent so far (excluding 'input')
     * @param machine The state machine
     * @param determinedQuirks The list of determined issues
     */
    private void checkSuccessorStateRedundancy(
            Object currentState,
            Object successorState,
            TlsWord input,
            List<TlsWord> allowedInputs,
            Stack<TlsWord> messageStack,
            StateMachine machine,
            List<StateMachineIssue> determinedQuirks) {
        // only test if it won't we reported as incompatibility
        if (!graphDetails.getErrorStates().contains(successorState)) {
            Stack<TlsWord> nextMessageStack = new Stack<>();
            nextMessageStack.addAll(messageStack);
            nextMessageStack.add(input);
            TransitionAnalyzer nextTransitionAnalyzer =
                    transitionAnalyzerProvider.getTransitionAnalyzer(nextMessageStack, machine);
            for (TlsWord alternativeInput : allowedInputs) {
                Object alternativeSuccessorState =
                        machine.getMealyMachine().getSuccessor(currentState, input);
                if (!alternativeInput.equals(input)
                        && alternativeSuccessorState != successorState
                        && !graphDetails.getErrorStates().contains(alternativeSuccessorState)
                        && nextTransitionAnalyzer.yieldsEqualSuccessorsAsLast(
                                alternativeInput.getType())) {
                    if (!graphDetails
                            .getRedundantBenignStates()
                            .contains(alternativeSuccessorState)) {
                        determinedQuirks.add(
                                new RedundantBenignStateIssue(
                                        currentState,
                                        successorState,
                                        alternativeSuccessorState,
                                        "",
                                        input,
                                        alternativeInput,
                                        new LinkedList<>(messageStack)));
                    }
                    graphDetails.getRedundantBenignStates().add(alternativeSuccessorState);
                }
            }
        }
    }

    private void addTransitionToState(Object state, TlsWord input, Object modeledTransition) {
        if (!stateInputMap.containsKey(state)) {
            stateInputMap.put(state, new HashSet<>());
        }
        stateInputMap.get(state).add(input);
        graphDetails.getStateInfo(state).addBenignInput(input);
        graphDetails.getHappyFlowsTransitions().add(modeledTransition);
    }

    /**
     * We expect transitions to an error state to come with an alert or no message. If a Heartbeat
     * has been cached, it may appear, too.
     *
     * @param output
     * @return true if the transition contains an unexpected response
     */
    public static boolean responseToErrorStateIsUnexpected(SulResponse output) {
        return responseToErrorStateIsUnexpected(output, null);
    }

    public static boolean responseToErrorStateIsUnexpected(
            SulResponse output, TlsWord benignInput) {
        if (benignInput != null
                && TlsWordType.effectivelyEquals(TlsWordType.ANY_APP_DATA, benignInput.getType())) {
            // allow app data for closing transitions when we sent app data as an allowed input
            // before
            return output.responseContainsMessagesOtherThan(
                    ApplicationMessage.class, AlertMessage.class, HeartbeatMessage.class);
        } else {
            return output.responseContainsMessagesOtherThan(
                    AlertMessage.class, HeartbeatMessage.class);
        }
    }
}
