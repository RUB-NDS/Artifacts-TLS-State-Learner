/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.analysis;

import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.algorithm.words.HRREnforcingClientHelloWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.HelloWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.Analyzer;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.core.util.TestUtils;
import de.rub.nds.statevulnfinder.server.extraction.TlsServerSulProvider;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsscanner.core.vector.response.EqualityError;
import de.rub.nds.tlsscanner.core.vector.response.FingerprintChecker;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import net.automatalib.words.Alphabet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StateMachineComparator {

    public static final double CONFIDENCE_EDGE_FACTOR = 3;
    public static final boolean INCLUDE_STATE_NAMES = true;
    public static final boolean DROP_LOW_CONFIDENCE_IDENTICAL = true;
    public static final boolean IGNORE_WHEN_BOTH_ARE_ILLEGAL_LEARNER = true;
    public static final boolean IGNORE_WHEN_ONE_IS_ILLEGAL_LEARNER = true;
    public static final int SOCKET_STATE_ONE_ALIVE_DISPERITY_FACTOR = 1;
    private static final Logger LOG = LogManager.getLogger(StateMachineComparator.class.getName());

    public static ComparisonResult compare(
            StateMachine sm1, StateMachine sm2, GraphDetails detailsSm1, GraphDetails detailsSm2) {
        if (detailsSm2 == null) {
            detailsSm2 = new GraphDetails();
            Analyzer analyzer = new TlsServerSulProvider().getAnalyzer(detailsSm2);
            analyzer.findVulnerabilities(sm2);
        }
        boolean secondIsBase = sm1.getAlphabet().size() > sm2.getAlphabet().size();
        StateMachine baseMachine = secondIsBase ? sm2 : sm1;
        StateMachine comparatorMachine = secondIsBase ? sm1 : sm2;

        GraphDetails detailsBase = secondIsBase ? detailsSm2 : detailsSm1;
        GraphDetails detailsComparison = secondIsBase ? detailsSm1 : detailsSm2;

        Alphabet<TlsWord> baseAlphabet = baseMachine.getAlphabet();
        Alphabet<TlsWord> comparatorAlphabet = comparatorMachine.getAlphabet();
        // ensure deterministic graph tracing
        List<TlsWord> sortedBaseAlphabet = new LinkedList<>(baseAlphabet);
        sortedBaseAlphabet.sort(Comparator.comparing(Object::toString));
        Map<TlsWord, TlsWord> sharedAlphabetMap =
                getSharedAlphabetMap(sortedBaseAlphabet, comparatorAlphabet);

        ComparisonResult result =
                compareEdges(
                        baseMachine,
                        comparatorMachine,
                        sharedAlphabetMap,
                        detailsBase,
                        detailsComparison,
                        sortedBaseAlphabet);

        // We need at least CONFIDENCE_EDGE_FACTOR * the number of meaningful inputs compared to
        // have some confidence
        int lowConfidenceThreshold =
                determineLowConfidenceThreshold(baseMachine, sharedAlphabetMap);
        result.setLowConfidence(result.getEdgesTested() <= lowConfidenceThreshold);

        if (INCLUDE_STATE_NAMES) {
            result.setSimilarity(
                    (double) (result.getEdgesMatched() + result.getStateNamesMatching())
                            / (result.getEdgesTested() + result.getStateNamesCompared()));
        } else {
            result.setSimilarity((double) result.getEdgesMatched() / result.getEdgesTested());
        }
        LOG.debug(
                "States compared {}, states matching {}",
                result.getStateNamesCompared(),
                result.getStateNamesMatching());

        result.setSharedAlphabetSize(sharedAlphabetMap.size());

        if (DROP_LOW_CONFIDENCE_IDENTICAL
                && result.isLowConfidence()
                && result.getSimilarity() >= 0.95) {
            result.setSimilarity(0.0);
        }
        LOG.info("Done comparing.");
        return result;
    }

    private static GraphDetails provideGraphDetailsForMachine(StateMachine machine) {
        GraphDetails details = new GraphDetails();
        Analyzer analyzer = new TlsServerSulProvider().getAnalyzer(details);
        analyzer.findVulnerabilities(machine);
        return details;
    }

    public static void massCompareToListed(
            StateMachine sm1,
            String pathToComparatorList,
            String pathToOutput,
            String myName,
            GraphDetails detailsSm1) {
        try (BufferedReader reader = Files.newBufferedReader(Paths.get(pathToComparatorList));
                BufferedWriter writer =
                        Files.newBufferedWriter(
                                Paths.get(pathToOutput),
                                StandardOpenOption.CREATE,
                                StandardOpenOption.APPEND)) {

            String line;
            while ((line = reader.readLine()) != null) {
                StateMachine comparatorMachine = TestUtils.loadStateMachine(line);
                Path comparatorPath = Paths.get(line);
                ComparisonResult result = compare(sm1, comparatorMachine, detailsSm1, null);
                String resultString =
                        comparatorPath.getFileName().toString().replace(".xml", "")
                                + ","
                                + result.getSimilarity()
                                + ","
                                + result.getEdgesTested()
                                + "( Alphabet: "
                                + result.getSharedAlphabetSize()
                                + ")";
                writer.write(resultString);
                writer.newLine();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void massCompareFolder(String path) {
        List<ComparisonEntry> entries = new LinkedList<>();
        readComparisonEntries(path, entries);
        // ensure determinstic comparison pairing
        entries.sort(Comparator.comparing(entry -> entry.getName()));
        List<ComparisonResult> results = crossCompareAllEntries(entries);
        writeResults(results);
        computeAndReportStatistics(results);
        computeAndReportEdgeStatistics(results);
    }

    private static void writeResults(List<ComparisonResult> results) {
        LOG.info("Writing results to comparisonResults.csv");
        try (BufferedWriter writer =
                Files.newBufferedWriter(
                        Paths.get("comparisonResults.csv"),
                        StandardOpenOption.CREATE,
                        StandardOpenOption.WRITE)) {
            writer.write("Source,Target,Weight,EdgesTested,AlphabetSize");
            writer.newLine();
            for (ComparisonResult result : results) {
                writer.write(
                        result.getIdentifier()
                                + ","
                                + result.getSimilarity()
                                + ","
                                + result.getEdgesTested()
                                + ","
                                + result.getSharedAlphabetSize());
                writer.newLine();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void readComparisonEntries(String path, List<ComparisonEntry> entries) {
        File directory = new File(path);
        if (!directory.isDirectory()) {
            System.out.println("The provided path is not a directory: " + path);
            return;
        }
        FilenameFilter xmlFilter =
                new FilenameFilter() {
                    @Override
                    public boolean accept(File dir, String name) {
                        return name.toLowerCase().endsWith(".xml");
                    }
                };
        File[] xmlFiles = directory.listFiles(xmlFilter);

        if (xmlFiles == null || xmlFiles.length == 0) {
            LOG.info("No XML files found in the directory: {}", path);
            return;
        }

        LOG.info("Reading {} XML files", xmlFiles.length);

        // Use a thread-safe list to store entries
        List<ComparisonEntry> threadSafeEntries = Collections.synchronizedList(entries);

        // Create a fixed thread pool with 10 threads
        ExecutorService executor = Executors.newFixedThreadPool(250);

        // Counter for processed files
        AtomicInteger ctr = new AtomicInteger(0);

        // Submit tasks for processing XML files
        for (File xmlFile : xmlFiles) {
            executor.submit(
                    () -> {
                        String xmlFilePath = xmlFile.getAbsolutePath();
                        try {
                            // Call the TestUtil.loadStateMachine method
                            StateMachine newStateMachine = TestUtils.loadStateMachine(xmlFilePath);
                            GraphDetails details = provideGraphDetailsForMachine(newStateMachine);

                            threadSafeEntries.add(
                                    new ComparisonEntry(
                                            newStateMachine,
                                            details,
                                            xmlFile.toPath()
                                                    .getFileName()
                                                    .toString()
                                                    .replace(".xml", "")));
                            int count = ctr.incrementAndGet();
                            LOG.info("Read {} state machines", count);
                        } catch (Exception e) {
                            LOG.error("Failed to process file: {}", xmlFilePath, e);
                        }
                    });
        }

        // Shutdown the executor and wait for tasks to finish
        executor.shutdown();
        try {
            // Wait for all tasks to complete or timeout after a certain period
            if (!executor.awaitTermination(1, TimeUnit.HOURS)) {
                executor.shutdownNow();
                LOG.warn("Executor did not terminate in the specified time.");
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
            LOG.error("Thread interrupted while waiting for executor to terminate.", e);
        }
    }

    private static List<ComparisonResult> crossCompareAllEntries(List<ComparisonEntry> entries) {
        List<ComparisonResult> results = Collections.synchronizedList(new LinkedList<>());
        long toCompare = (entries.size() * (entries.size() - 1)) / 2;
        AtomicLong compared = new AtomicLong(0);

        // Create a fixed thread pool
        ExecutorService executor = Executors.newFixedThreadPool(250);

        for (int i = 0; i < entries.size(); i++) {
            for (int j = i + 1; j < entries.size(); j++) {
                ComparisonEntry entry1 = entries.get(i);
                ComparisonEntry entry2 = entries.get(j);

                executor.submit(
                        () -> {
                            try {
                                LOG.info("Comparing {} to {}", entry1.getName(), entry2.getName());
                                ComparisonResult result =
                                        compare(
                                                entry1.getStateMachine(),
                                                entry2.getStateMachine(),
                                                entry1.getGraphDetails(),
                                                entry2.getGraphDetails());

                                LOG.info(
                                        "Comparing {} to {}: Similarity: {}, Edges: {}",
                                        entry1.getName(),
                                        entry2.getName(),
                                        result.getSimilarity(),
                                        result.getEdgesTested());

                                long currentCompared = compared.incrementAndGet();

                                result.setIdentifier(entry1.getName() + "," + entry2.getName());
                                results.add(result);

                                LOG.info("Compared {}/{}", currentCompared, toCompare);
                            } catch (Exception e) {
                                LOG.error("Failed to compare state machines", e);
                            }
                        });
            }
        }

        // Shutdown the executor and wait for tasks to finish
        executor.shutdown();
        try {
            // Wait for all tasks to complete or timeout after a certain period
            if (!executor.awaitTermination(1, TimeUnit.HOURS)) {
                executor.shutdownNow();
                LOG.warn("Executor did not terminate in the specified time.");
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
            LOG.error("Thread interrupted while waiting for executor to terminate.", e);
        }
        return results;
    }

    public static Map<TlsWord, TlsWord> getSharedAlphabetMap(
            List<TlsWord> baseAlphabet, Alphabet<TlsWord> comparisonAlphabet) {
        HashMap<TlsWord, TlsWord> sharedAlphabetMap = new HashMap<>();
        for (TlsWord word : baseAlphabet) {
            if (word == null) {
                LOG.warn("Tried to find equivalent for null.");
                continue;
            }
            TlsWord equivalent = getEquivalent(word, comparisonAlphabet);
            if (equivalent != null) {
                sharedAlphabetMap.put(word, equivalent);
            }
        }
        return sharedAlphabetMap;
    }

    private static TlsWord getEquivalent(TlsWord word, Alphabet<TlsWord> comparisonAlphabet) {
        TlsWord equivalent = null;
        for (TlsWord comparisonWord : comparisonAlphabet) {
            if (getSimplifiedWordString(word).equals(getSimplifiedWordString(comparisonWord))) {
                if (equivalent == null) {
                    equivalent = comparisonWord;
                } else {
                    LOG.warn("Multiple equivalent words found for {}", word);
                }
            }
        }
        return equivalent;
    }

    private static String getSimplifiedWordString(TlsWord word) {
        if (word instanceof HelloWord) {
            HelloWord helloWord = (HelloWord) word;
            CipherSuite cipherSuite = helloWord.getSuite();
            String suiteString;
            if (cipherSuite.isTLS13()) {
                suiteString = "TLS13";
            } else {
                suiteString =
                        AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite).name().split("_")[0]
                                + "+"
                                + AlgorithmResolver.getCipherType(cipherSuite).name();
            }

            if (word instanceof HRREnforcingClientHelloWord) {
                return "HRREnforcingClientHello{" + suiteString + "}";
            } else {
                return helloWord.getHelloType() + "HelloWord{suite=" + suiteString + '}';
            }
        }
        return word.toString();
    }

    public static ComparisonResult compareEdges(
            StateMachine baseMachine,
            StateMachine comparisonMachine,
            Map<TlsWord, TlsWord> sharedAlphabetMap,
            GraphDetails detailsBase,
            GraphDetails detailsComparison,
            List<TlsWord> sortedBaseAlphabet) {
        ComparisonResult result = new ComparisonResult();
        List<Object> coveredStates = new LinkedList<>();
        // ignore all dummy states as all outgoing edges must be identical - if there is a
        // difference in the path, it must already be observable before we go there
        coveredStates.addAll(AnalysisUtil.getDummyStates(baseMachine));
        Object currentStateBase = baseMachine.getMealyMachine().getInitialState();
        Object currentStateOther = comparisonMachine.getMealyMachine().getInitialState();
        return compareEdgesInner(
                baseMachine,
                comparisonMachine,
                sharedAlphabetMap,
                coveredStates,
                currentStateBase,
                currentStateOther,
                result,
                detailsBase,
                detailsComparison,
                sortedBaseAlphabet);
    }

    private static ComparisonResult compareEdgesInner(
            StateMachine baseMachine,
            StateMachine comparisonMachine,
            Map<TlsWord, TlsWord> sharedAlphabetMap,
            List<Object> coveredStates,
            Object currentStateBase,
            Object currentStateOther,
            ComparisonResult result,
            GraphDetails detailsBase,
            GraphDetails detailsComparison,
            List<TlsWord> sortedBaseAlphabet) {
        if (coveredStates.contains(currentStateBase)) {
            // already considered all edges of this
            return result;
        }
        if (INCLUDE_STATE_NAMES) {
            evaluateStateNames(
                    currentStateBase,
                    currentStateOther,
                    detailsBase,
                    detailsComparison,
                    result,
                    sharedAlphabetMap);
        }
        coveredStates.add(currentStateBase);
        LOG.debug("Comparing state {} to state {}", currentStateBase, currentStateOther);
        for (TlsWord baseInput : sortedBaseAlphabet) {
            if (detailsBase.getErrorStates().contains(currentStateBase)
                    && detailsComparison.getErrorStates().contains(currentStateOther)
                    && baseInput.getType() != TlsWordType.RESET_CONNECTION) {
                // Skip over inputs other then RST when we are in an error state. All outgoing edges
                // must be identical by definition so they would lower the influence of differing
                // edges.
                continue;
            }

            TlsWord equivalent = sharedAlphabetMap.get(baseInput);
            if (equivalent == null) {
                // no equivalent in the other alphabet
                continue;
            }
            Object nextStateBase =
                    baseMachine.getMealyMachine().getSuccessor(currentStateBase, baseInput);
            Object nextStateOther =
                    comparisonMachine.getMealyMachine().getSuccessor(currentStateOther, equivalent);
            SulResponse outputBase =
                    (SulResponse)
                            baseMachine.getMealyMachine().getOutput(currentStateBase, baseInput);
            SulResponse outputOther =
                    (SulResponse)
                            comparisonMachine
                                    .getMealyMachine()
                                    .getOutput(currentStateOther, equivalent);
            LOG.debug(
                    "Output base: {}, output other: {}",
                    outputBase == null ? "null" : outputBase.toString(),
                    outputOther == null ? "null" : outputOther.toString());
            boolean bothLoop =
                    nextStateBase == currentStateBase && nextStateOther == currentStateOther;
            boolean bothChange =
                    nextStateBase != currentStateBase && nextStateOther != currentStateOther;
            boolean stateChangeMatches = bothLoop || bothChange;
            if (IGNORE_WHEN_BOTH_ARE_ILLEGAL_LEARNER
                    && outputBase.isIllegalTransitionFlag()
                    && outputOther.isIllegalTransitionFlag()) {
                // tracing any further won't change anything and we don't want to count this edge
                continue;
            } else if (IGNORE_WHEN_ONE_IS_ILLEGAL_LEARNER
                    && (outputBase.isIllegalTransitionFlag()
                            || outputOther.isIllegalTransitionFlag())) {
                // tracing any further won't change anything and we don't want to count this edge
                continue;
            }
            boolean bothSentCertificate =
                    !AnalysisUtil.getMessagesFromResponse(outputBase, CertificateMessage.class)
                                    .isEmpty()
                            && !AnalysisUtil.getMessagesFromResponse(
                                            outputBase, CertificateMessage.class)
                                    .isEmpty();

            if (stateChangeMatches
                    && responsesMatch(bothSentCertificate, outputBase, outputOther)) {
                result.edgeMatched();
                // continue tracing a path
                result =
                        compareEdgesInner(
                                baseMachine,
                                comparisonMachine,
                                sharedAlphabetMap,
                                coveredStates,
                                nextStateBase,
                                nextStateOther,
                                result,
                                detailsBase,
                                detailsComparison,
                                sortedBaseAlphabet);
            } else {
                LOG.debug(
                        "Offending output in state {} vs {} for {}: \n{}\n vs\n{}",
                        currentStateBase,
                        currentStateOther,
                        baseInput.toString(),
                        outputBase,
                        outputOther);
                if (isDeadVsAliveSocketStateDifference(outputBase, outputOther)) {
                    for (int i = 0; i < sharedAlphabetMap.keySet().size() - 1; i++) {
                        result.edgeDiffers();
                    }
                }
                // one triggered a state change, the other did not or response didn't match
                result.edgeDiffers();
            }
            // regardless of success, keep testing for other inputs in this state
        }
        return result;
    }

    private static boolean responsesMatch(
            boolean bothSentCertificate, SulResponse outputBase, SulResponse outputOther) {
        if (!bothSentCertificate) {
            return outputBase.equals(outputOther);
        }
        EqualityError equalityError =
                FingerprintChecker.checkEquality(
                        outputBase.getResponseFingerprint(), outputOther.getResponseFingerprint());
        return equalityError == EqualityError.NONE
                || equalityError == EqualityError.RECORD_CONTENT
                || equalityError == EqualityError.RECORD_COUNT;
    }

    private static boolean isDeadVsAliveSocketStateDifference(
            SulResponse outputBase, SulResponse outputOther) {
        List<SocketState> statesAlive = List.of(SocketState.UP, SocketState.DATA_AVAILABLE);
        List<SocketState> statesDead =
                List.of(
                        SocketState.CLOSED,
                        SocketState.PEER_WRITE_CLOSED,
                        SocketState.TIMEOUT,
                        SocketState.IO_EXCEPTION);
        List<SocketState> states = new ArrayList<>();
        if (!outputBase.isIllegalTransitionFlag() && !outputOther.isIllegalTransitionFlag()) {
            states.add(outputBase.getResponseFingerprint().getSocketState());
            states.add(outputOther.getResponseFingerprint().getSocketState());
            boolean anyAlive = statesAlive.stream().anyMatch(states::contains);
            boolean anyDead = statesDead.stream().anyMatch(states::contains);
            return anyAlive && anyDead;
        }
        return false;
    }

    private static void evaluateStateNames(
            Object stateBase,
            Object stateOther,
            GraphDetails detailsBase,
            GraphDetails detailsOther,
            ComparisonResult result,
            Map<TlsWord, TlsWord> sharedAlphabetMap) {
        Set<String> namesStateBase =
                detailsBase.hasStateInfo(stateBase)
                        ? detailsBase.getStateInfo(stateBase).getNames().stream()
                                .filter(name -> typeIsInSharedAlphabet(name, sharedAlphabetMap))
                                .collect(Collectors.toSet())
                        : new HashSet<>();
        if (detailsBase.getErrorStates().contains(stateBase)) {
            namesStateBase.add("ERROR");
        }
        Set<String> namesStateOther =
                detailsOther.hasStateInfo(stateOther)
                        ? detailsOther.getStateInfo(stateOther).getNames().stream()
                                .filter(name -> typeIsInSharedAlphabet(name, sharedAlphabetMap))
                                .collect(Collectors.toSet())
                        : new HashSet<>();
        if (detailsOther.getErrorStates().contains(stateOther)) {
            namesStateOther.add("ERROR");
        }
        LOG.debug("State names base: {}, state names other: {}", namesStateBase, namesStateOther);
        Set<String> jointStates = new HashSet<>(namesStateBase);
        jointStates.retainAll(namesStateOther);
        Set<String> disjointStates = new HashSet<>(namesStateBase);
        disjointStates.addAll(namesStateOther);
        disjointStates.removeAll(jointStates);
        result.updateStateNameComparison(
                jointStates.size() + disjointStates.size(), jointStates.size());
    }

    // Filter out state names which are not in the shared alphabet
    private static boolean typeIsInSharedAlphabet(
            String stateName, Map<TlsWord, TlsWord> sharedAlphabetMap) {
        for (TlsWord word : sharedAlphabetMap.keySet()) {
            if (word.getType().name().equals(stateName)) {
                return true;
            }
        }
        return false;
    }

    private static void computeAndReportStatistics(List<ComparisonResult> results) {
        // Collect all similarity scores
        List<Double> similarities =
                results.stream().map(ComparisonResult::getSimilarity).collect(Collectors.toList());

        if (similarities.isEmpty()) {
            LOG.info("No similarities to compute statistics.");
            return;
        }

        // Compute average similarity
        double averageSimilarity =
                similarities.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);

        // Compute deciles
        Collections.sort(similarities);
        double min = similarities.get(0);
        double max = similarities.get(similarities.size() - 1);
        double percentile25 = getPercentile(similarities, 25);
        double percentile50 = getPercentile(similarities, 50);
        double percentile75 = getPercentile(similarities, 75);

        LOG.info("Similarity Statistics:");
        LOG.info("Minimum Similarity (0%): {}", min);
        LOG.info("25th Percentile Similarity: {}", percentile25);
        LOG.info("Median Similarity (50%): {}", percentile50);
        LOG.info("75th Percentile Similarity: {}", percentile75);
        LOG.info("Maximum Similarity (100%): {}", max);
        LOG.info("Average Similarity: {}", averageSimilarity);

        // Identify entries significantly below the average (e.g., more than one standard deviation
        // below average)
        double standardDeviation = computeStandardDeviation(similarities, averageSimilarity);

        double threshold = averageSimilarity - standardDeviation;

        List<String> lowSimilarityEntries = new ArrayList<>();

        // Map to keep track of entries and their average similarities
        Map<String, List<Double>> entrySimilarityMap = new HashMap<>();

        for (ComparisonResult result : results) {
            String[] identifiers = result.getIdentifier().split(",");
            String entry1 = identifiers[0];
            String entry2 = identifiers[1];
            double similarity = result.getSimilarity();

            entrySimilarityMap.computeIfAbsent(entry1, k -> new ArrayList<>()).add(similarity);
            entrySimilarityMap.computeIfAbsent(entry2, k -> new ArrayList<>()).add(similarity);
        }

        // Check each entry's average similarity
        for (Map.Entry<String, List<Double>> entry : entrySimilarityMap.entrySet()) {
            double entryAverage =
                    entry.getValue().stream()
                            .mapToDouble(Double::doubleValue)
                            .average()
                            .orElse(0.0);

            if (entryAverage < threshold) {
                lowSimilarityEntries.add(entry.getKey());
            }
        }

        LOG.info(
                "Entries with average similarity significantly below the overall average (threshold: {}):",
                threshold);
        for (String entry : lowSimilarityEntries) {
            LOG.info(" - {}", entry);
        }
        LOG.info("Total entries significantly below average: {}", lowSimilarityEntries.size());
    }

    private static double getPercentile(List<Double> sortedList, double percentile) {
        int index = (int) Math.ceil(percentile / 100.0 * sortedList.size()) - 1;
        return sortedList.get(Math.max(0, Math.min(index, sortedList.size() - 1)));
    }

    private static Long getPercentileLong(List<Long> sortedList, double percentile) {
        int index = (int) Math.ceil(percentile / 100.0 * sortedList.size()) - 1;
        return sortedList.get(Math.max(0, Math.min(index, sortedList.size() - 1)));
    }

    private static double computeStandardDeviation(List<Double> similarities, double mean) {
        double variance =
                similarities.stream().mapToDouble(s -> Math.pow(s - mean, 2)).average().orElse(0.0);
        return Math.sqrt(variance);
    }

    private static void computeAndReportEdgeStatistics(List<ComparisonResult> results) {
        // Collect all edges tested
        List<Long> edgesTestedList =
                results.stream().map(ComparisonResult::getEdgesTested).collect(Collectors.toList());

        if (edgesTestedList.isEmpty()) {
            LOG.info("No edge data to compute statistics.");
            return;
        }

        // Compute average edges tested
        double averageEdgesTested =
                edgesTestedList.stream().mapToInt(Long::intValue).average().orElse(0.0);

        // Compute percentiles
        Collections.sort(edgesTestedList);
        Long min = edgesTestedList.get(0);
        Long max = edgesTestedList.get(edgesTestedList.size() - 1);
        Long percentile25 = getPercentileLong(edgesTestedList, 25);
        Long percentile50 = getPercentileLong(edgesTestedList, 50);
        Long percentile75 = getPercentileLong(edgesTestedList, 75);

        LOG.info("Edges Tested Statistics:");
        LOG.info("Minimum Edges Tested (0%): {}", min);
        LOG.info("25th Percentile Edges Tested: {}", percentile25);
        LOG.info("Median Edges Tested (50%): {}", percentile50);
        LOG.info("75th Percentile Edges Tested: {}", percentile75);
        LOG.info("Maximum Edges Tested (100%): {}", max);
        LOG.info("Average Edges Tested: {}", averageEdgesTested);

        // Identify entries with exclusively low edges tested values
        // Define a threshold for low edges tested (e.g., entries below 25th percentile)
        double threshold = percentile25;

        List<String> lowEdgesEntries = new ArrayList<>();

        // Map to keep track of entries and their edges tested values
        Map<String, List<Long>> entryEdgesTestedMap = new HashMap<>();

        for (ComparisonResult result : results) {
            String[] identifiers = result.getIdentifier().split(",");
            String entry1 = identifiers[0];
            String entry2 = identifiers[1];
            long edgesTested = result.getEdgesTested();

            entryEdgesTestedMap.computeIfAbsent(entry1, k -> new ArrayList<>()).add(edgesTested);
            entryEdgesTestedMap.computeIfAbsent(entry2, k -> new ArrayList<>()).add(edgesTested);
        }

        // Check each entry's edges tested values
        for (Map.Entry<String, List<Long>> entry : entryEdgesTestedMap.entrySet()) {
            List<Long> edgesTestedValues = entry.getValue();
            boolean allLow = edgesTestedValues.stream().allMatch(e -> e <= threshold);

            if (allLow) {
                lowEdgesEntries.add(entry.getKey());
            }
        }

        LOG.info("Entries with exclusively low edges tested values (threshold: {}):", threshold);
        for (String entry : lowEdgesEntries) {
            LOG.info(" - {}", entry);
        }
        LOG.info("Total entries with exclusively low edges tested: {}", lowEdgesEntries.size());
    }

    private static int determineLowConfidenceThreshold(
            StateMachine stateMachine, Map<TlsWord, TlsWord> sharedAlphabetMap) {
        int nonIllegalTransitionsInStart = 0;
        Object startState = stateMachine.getMealyMachine().getInitialState();
        for (TlsWord sharedInput : sharedAlphabetMap.keySet()) {
            SulResponse output =
                    (SulResponse) stateMachine.getMealyMachine().getOutput(startState, sharedInput);
            if (!output.isIllegalTransitionFlag()) {
                nonIllegalTransitionsInStart++;
            }
        }
        return (int) CONFIDENCE_EDGE_FACTOR * nonIllegalTransitionsInStart;
    }
}
