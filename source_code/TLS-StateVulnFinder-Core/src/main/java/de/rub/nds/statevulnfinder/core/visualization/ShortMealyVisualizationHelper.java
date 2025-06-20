/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.visualization;

import de.rub.nds.statevulnfinder.core.algorithm.words.BleichenbacherWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.PaddingOracleWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.analysis.TlsBenignStateInfo;
import de.rub.nds.statevulnfinder.core.analysis.transitions.ContextProperty;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.constants.VisualizationDetail;
import de.rub.nds.statevulnfinder.core.issue.BBAndPOVulnerability;
import de.rub.nds.statevulnfinder.core.issue.DivergingBleichenbacherVulnerability;
import de.rub.nds.statevulnfinder.core.issue.DivergingPaddingOracleVulnerability;
import de.rub.nds.statevulnfinder.core.issue.SameStateBleichenbacherVulnerability;
import de.rub.nds.statevulnfinder.core.issue.SameStatePaddingOracleVulnerability;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import java.util.*;
import net.automatalib.automata.graphs.TransitionEdge;
import net.automatalib.automata.transducers.MealyMachine;
import net.automatalib.automata.transducers.TransitionOutputAutomaton;
import net.automatalib.automata.visualization.AutomatonVisualizationHelper;
import net.automatalib.words.Alphabet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ShortMealyVisualizationHelper
        extends AutomatonVisualizationHelper<
                Object,
                TlsWord,
                Object,
                TransitionOutputAutomaton<Object, TlsWord, Object, SulResponse>> {

    private static final Logger LOG = LogManager.getLogger();

    private static final String COLOR_UNSPECIFIED_KNOWN_STATE = "PEACHPUFF";
    private static final String COLOR_TLS_1_3 = "GREEN";
    private static final String COLOR_TLS_1_3_CAN_RESUME = "OLIVE";
    private static final String COLOR_TLS_1_3_RESUMPTION = "SPRINGGREEN";
    private static final String COLOR_TLS_1_2 = "BLUE";
    private static final String COLOR_TLS_1_2_CAN_RESUME = "DARKCYAN";
    private static final String COLOR_TLS_1_2_RESUMPTION = "CYAN";
    private static final String COLOR_TLS_1_2_RENEGOTIATION = "PURPLE";

    GraphDetails graphDetails;
    Map<String, String> nodeNames;
    VisualizationDetail detail;
    Alphabet<TlsWord> alphabet;
    // counts how many transitions go from a state to another state
    Map<Object, Map<Object, Integer>> successorCount;
    // collects transitions from a node by their fingerprint
    Map<Object, Map<SulResponse, Set<Object>>> transitions;
    Map<Object, Map<SulResponse, Boolean>> alreadyPrintedOtherMedium;
    Map<Object, Map<SulResponse, Boolean>> alreadyPrintedAnyMedium;
    Set<Object> alreadyPrintedOtherShort;
    Set<Object> alreadyPrintedAnyShort;
    Map<Object, Collection<Object>> alreadyPrintedBB;
    Map<Object, Collection<ProtocolMessageType>> alreadyPrintedPO;
    private final List<Object> bleichenbacherEdges;
    private final List<Object> paddingoracleEdges;
    private final Set<Object> happyFlowTransitions;
    private final Set<Object> vulnTransitions;

    public ShortMealyVisualizationHelper(
            MealyMachine automaton, GraphDetails graphDetails, Alphabet<TlsWord> alphabet) {
        // we default to no detail pruning
        this(automaton, graphDetails, VisualizationDetail.LONG, alphabet);
    }

    public ShortMealyVisualizationHelper(
            MealyMachine mealyMachine,
            GraphDetails graphDetails,
            VisualizationDetail detail,
            Alphabet<TlsWord> alphabet) {
        super(mealyMachine);
        this.alphabet = alphabet;
        this.graphDetails = graphDetails;
        this.nodeNames = graphDetails.getNodeNames();
        this.happyFlowTransitions = graphDetails.getHappyFlowsTransitions();
        // contains transitions of the most dire vulnerability in the graph
        this.vulnTransitions = graphDetails.getTopVulnerabilityPath((MealyMachine) mealyMachine);
        this.detail = detail;
        this.successorCount = new HashMap<>();
        this.bleichenbacherEdges = new LinkedList<>();
        this.paddingoracleEdges = new LinkedList<>();
        this.alreadyPrintedOtherShort = new HashSet<>();
        this.alreadyPrintedAnyShort = new HashSet<>();
        this.alreadyPrintedOtherMedium = new HashMap<>();
        this.alreadyPrintedAnyMedium = new HashMap<>();
        this.alreadyPrintedBB = new HashMap<>();
        this.alreadyPrintedPO = new HashMap<>();
        for (Object state : mealyMachine.getStates()) {
            alreadyPrintedOtherMedium.put(state, new HashMap<>());
            alreadyPrintedAnyMedium.put(state, new HashMap<>());
            alreadyPrintedBB.put(state, new HashSet<>());
            alreadyPrintedPO.put(state, new HashSet<>());
        }
        transitions = new HashMap<>();
        preAnalysis();
    }

    @Override
    public boolean getEdgeProperties(
            Object src,
            TransitionEdge<TlsWord, Object> edge,
            Object tgt,
            Map<String, String> properties) {
        if (!super.getEdgeProperties(src, edge, tgt, properties)) {
            return false;
        }
        switch (detail) {
            case SHORT:
            case MEDIUM:
                return visualizeShortOrMedium(src, edge, tgt, properties, detail);

            default:
                // we default to the long case
                return visualizeLong(edge, properties);
        }
    }

    private boolean visualizeShortOrMedium(
            Object src,
            TransitionEdge<TlsWord, Object> edge,
            Object tgt,
            Map<String, String> properties,
            VisualizationDetail detail) {
        if (happyFlowTransitions == null) {
            LOG.error(
                    "GraphDetails have not been analyzed properly - failed to provide visualization");
            return false;
        }
        if (happyFlowTransitions.contains(edge.getTransition())) {
            // inherit color from target node (green if not specified)
            paintEdge(properties, getColorForKnownNode(tgt), "", "");
        }
        if (vulnTransitions.contains(edge.getTransition())) {
            // all vulnerability edges are painted orange unless they point to the finished state or
            // yield a CCS/FIN
            if (graphDetails.getFinStates().contains(tgt)
                    || (graphDetails.getCriticalOutputTransitions() != null
                            && graphDetails
                                    .getCriticalOutputTransitions()
                                    .contains(edge.getTransition()))) {
                paintEdge(properties, "RED", "bold", getShortEdgeName(edge));
            } else {
                paintEdge(properties, "ORANGE", "bold", getShortEdgeName(edge));
            }
        } else if (edge.getInput() instanceof BleichenbacherWord
                && bleichenbacherEdges.contains(edge.getTransition())) {
            // bleichenbacher vulnerabilites are painted red
            paintEdge(properties, "RED", "bold", getShortEdgeName(edge));
        } else if (edge.getInput() instanceof PaddingOracleWord
                && paddingoracleEdges.contains(edge.getTransition())) {
            // padding oracle vulnerabilites are painted red
            paintEdge(properties, "RED", "bold", getShortEdgeName(edge));
        } else if (successorCount.get(src).get(tgt) == 1) {
            // if only one transition from src to tgt: print it
            paintEdge(properties, "", "", getShortEdgeName(edge));
        } else if (successorCount.get(src).keySet().size() == 1) {
            // if all transitions go from src to tgt: print "any"
            return paintAnyEdge(src, edge, properties, detail);
        } else if (tgt.equals(getMaxFromMap(successorCount.get(src)))) {
            // if we have multiple transitions but this leads to the node that is reached by most
            return paintOtherEdge(src, edge, properties, detail);
        } else if (edge.getInput() instanceof BleichenbacherWord) {
            // between two nodes print only one bleichenbacher edge
            if (!alreadyPrintedBB.get(src).contains(tgt)) {
                paintEdge(properties, "", "", getShortEdgeName(edge));
                alreadyPrintedBB.get(src).add(tgt);
            } else {
                return false;
            }
        } else if (edge.getInput() instanceof PaddingOracleWord) {
            // print each po type only once
            ProtocolMessageType type =
                    ((PaddingOracleWord) edge.getInput()).getProtocolMessageType();
            if (!alreadyPrintedPO.get(src).contains(type)) {
                paintEdge(properties, "", "", getShortEdgeName(edge));
                alreadyPrintedPO.get(src).add(type);
            } else {
                return false;
            }
        } else {
            paintEdge(properties, "", "", getShortEdgeName(edge));
        }
        return true;
    }

    private boolean visualizeLong(
            TransitionEdge<TlsWord, Object> edge, Map<String, String> properties) {
        final StringBuilder longLabelBuilder = new StringBuilder();
        longLabelBuilder.append("Input: ").append(edge.getInput().toString()).append(" / ");
        SulResponse longOutput = automaton.getTransitionOutput(edge.getTransition());
        if (longOutput != null) {
            longLabelBuilder.append("Output: ").append(longOutput);
        }
        properties.put(EdgeAttrs.LABEL, longLabelBuilder.toString());
        return true;
    }

    private boolean paintAnyEdge(
            Object src,
            TransitionEdge<TlsWord, Object> edge,
            Map<String, String> properties,
            VisualizationDetail detail) {
        if (detail == VisualizationDetail.SHORT) {
            if (!alreadyPrintedAnyShort.contains(src)) {
                paintEdge(properties, "BLACK", "dotted", "any");
                alreadyPrintedAnyShort.add(src);
                return true;
            } else {
                return false;
            }
        } else {
            SulResponse sulResponse = automaton.getTransitionOutput(edge.getTransition());
            if (alreadyPrintedOtherMedium.get(src).get(sulResponse)) {
                // we already printed other for this responseFingerprint
                return false;
            } else {
                String name = "any|" + sulResponse.toShortString();
                paintEdge(properties, "BLACK", "dotted", name);
                alreadyPrintedOtherMedium.get(src).put(sulResponse, true);
                return true;
            }
        }
    }

    private boolean paintOtherEdge(
            Object src,
            TransitionEdge<TlsWord, Object> edge,
            Map<String, String> properties,
            VisualizationDetail detail) {
        if (detail == VisualizationDetail.SHORT) {
            if (!alreadyPrintedOtherShort.contains(src)) {
                paintEdge(properties, "BLACK", "dotted", "other");
                alreadyPrintedOtherShort.add(src);
                return true;
            } else {
                return false;
            }
        } else {
            SulResponse sulResponse = automaton.getTransitionOutput(edge.getTransition());
            if (alreadyPrintedOtherMedium.get(src).get(sulResponse)) {
                // we already printed other for this responseFingerprint
                return false;
            } else {
                String name = "other|" + sulResponse.toShortString();
                paintEdge(properties, "BLACK", "dotted", name);
                alreadyPrintedOtherMedium.get(src).put(sulResponse, true);
                return true;
            }
        }
    }

    private void paintEdge(
            Map<String, String> properties, String color, String style, String name) {
        if (!color.equals("")) {
            properties.put(EdgeAttrs.COLOR, color);
        }
        if (!style.equals("")) {
            properties.put(EdgeAttrs.STYLE, style);
        }
        if (!name.equals("")) {
            properties.put(EdgeAttrs.LABEL, name);
        }
    }

    @Override
    public boolean getNodeProperties(Object node, Map<String, String> properties) {
        if (!super.getNodeProperties(node, properties)) {
            // if the super method does not want to render the node, we probably do not want to
            // either
            return false;
        }
        // overwrite the Node label if we have a better name for it
        if (nodeNames.containsKey(node.toString())) {
            properties.put(NodeAttrs.LABEL, nodeNames.get(node.toString()) + "(" + node + ")");
            properties.put(NodeAttrs.STYLE, "bold");
            properties.put(NodeAttrs.COLOR, getColorForKnownNode(node));
        } else if (detail == VisualizationDetail.SHORT || detail == VisualizationDetail.MEDIUM) {
            // this node has no name associated - the anylsis result will indicate if it is critical or not
            properties.put(NodeAttrs.COLOR, "RED");
            properties.put(NodeAttrs.STYLE, "bold");
            properties.put(NodeAttrs.LABEL, "Unlabeled" + "(" + node + ")");
        }
        // we want to render the node
        properties.put(NodeAttrs.FIXEDSIZE, "true");
        properties.put(NodeAttrs.WIDTH, "2.3");
        properties.put(NodeAttrs.HEIGHT, "2.3");
        return true;
    }

    private String getColorForKnownNode(Object node) {
        if (graphDetails.getStateInfo(node) != null
                && graphDetails.getStateInfo(node).getVersionFlow()
                        == TlsBenignStateInfo.VersionFlow.TLS12) {
            boolean isRenegotiation =
                    graphDetails
                            .getStateInfo(node)
                            .reachedProperty(ContextProperty.ACCEPTED_RENEGOTIATION);
            boolean isResumption =
                    graphDetails
                            .getStateInfo(node)
                            .reachedProperty(ContextProperty.IN_RESUMPTION_FLOW);
            if (isRenegotiation) {
                return COLOR_TLS_1_2_RENEGOTIATION;
            } else if (isResumption) {
                return COLOR_TLS_1_2_RESUMPTION;
            } else {
                if (graphDetails
                        .getStateInfo(node)
                        .reachedProperty(ContextProperty.CAN_RESUME_CORRECTLY_TLS12)) {
                    return COLOR_TLS_1_2_CAN_RESUME;
                } else {
                    return COLOR_TLS_1_2;
                }
            }

        } else if (graphDetails.getStateInfo(node) != null
                && graphDetails.getStateInfo(node).getVersionFlow()
                        == TlsBenignStateInfo.VersionFlow.TLS13) {
            boolean isTls13Resumption =
                    graphDetails
                            .getStateInfo(node)
                            .reachedProperty(ContextProperty.IN_RESUMPTION_FLOW);
            if (isTls13Resumption) {
                return COLOR_TLS_1_3_RESUMPTION;
            } else {
                if (graphDetails
                        .getStateInfo(node)
                        .reachedProperty(ContextProperty.CAN_RESUME_CORRECTLY_TLS13)) {
                    return COLOR_TLS_1_3_CAN_RESUME;
                } else {
                    return COLOR_TLS_1_3;
                }
            }
        }

        return COLOR_UNSPECIFIED_KNOWN_STATE;
    }

    private String getShortEdgeName(TransitionEdge<TlsWord, Object> edge) {
        // method allows us to "overwrite" short strings which we deem to long manually
        return edge.getInput().toShortString()
                + "|"
                + automaton.getTransitionOutput(edge.getTransition()).toShortString();
    }

    private void preAnalysis() {
        // for each node:
        // save the responseFingerprints we can trigger from here together with their edges
        for (Object src : automaton.getStates()) {
            Map<SulResponse, Set<Object>> innerMap = new HashMap<>();
            transitions.put(src, innerMap);
            for (TlsWord tlsWord : alphabet) {
                Object trans = automaton.getTransition(src, tlsWord);
                SulResponse sulResponse = automaton.getTransitionOutput(trans);
                if (innerMap.containsKey(sulResponse)) {
                    innerMap.get(sulResponse).add(trans);
                } else {
                    Set<Object> transSet = new HashSet<>();
                    transSet.add(trans);
                    innerMap.put(sulResponse, transSet);
                    alreadyPrintedOtherMedium.get(src).put(sulResponse, false);
                    alreadyPrintedAnyMedium.get(src).put(sulResponse, false);
                }
            }
        }
        // for each node:
        // safe all nodes that are reachable with the amount of transitions that reach it
        for (Object src : automaton.getStates()) {
            Map<Object, Integer> innerMap = getEdgeNeighborCount(src);
            successorCount.put(src, innerMap);
        }
        // gather all bleichenbacher and paddingOracle edges
        for (StateMachineIssue vulnerability : graphDetails.getVulnListOnlyBBAndPO()) {
            if (vulnerability instanceof DivergingBleichenbacherVulnerability
                    || vulnerability instanceof SameStateBleichenbacherVulnerability) {
                BBAndPOVulnerability vuln = (BBAndPOVulnerability) vulnerability;
                bleichenbacherEdges.add(
                        automaton.getTransition(
                                (Object) vuln.getSourceNode(), vuln.getFirstWord()));
                bleichenbacherEdges.add(
                        automaton.getTransition(
                                (Object) vuln.getSourceNode(), vuln.getSecondWord()));
            } else if (vulnerability instanceof DivergingPaddingOracleVulnerability
                    || vulnerability instanceof SameStatePaddingOracleVulnerability) {
                BBAndPOVulnerability vuln = (BBAndPOVulnerability) vulnerability;
                paddingoracleEdges.add(
                        automaton.getTransition(
                                (Object) vuln.getSourceNode(), vuln.getFirstWord()));
                paddingoracleEdges.add(
                        automaton.getTransition(
                                (Object) vuln.getSourceNode(), vuln.getSecondWord()));
            }
        }
    }

    /**
     * Some java Stream, collection voodoo to return the element S with the highest count in the map
     */
    private Object getMaxFromMap(Map<Object, Integer> nodeMap) {
        Optional<Map.Entry<Object, Integer>> maxEntry =
                nodeMap.entrySet().stream().max(Map.Entry.comparingByValue());
        return maxEntry.get().getKey();
    }

    private Map<Object, Integer> getEdgeNeighborCount(Object srcState) {
        Map<Object, Integer> innerEdgeCountMap = new HashMap<>();
        for (TlsWord tlsWord : alphabet) {
            Object successor = automaton.getSuccessor(srcState, tlsWord);
            innerEdgeCountMap.put(successor, innerEdgeCountMap.getOrDefault(successor, 0) + 1);
        }
        return innerEdgeCountMap;
    }
}
