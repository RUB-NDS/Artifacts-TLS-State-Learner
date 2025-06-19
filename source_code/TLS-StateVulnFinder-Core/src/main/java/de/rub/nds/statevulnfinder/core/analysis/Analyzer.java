/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.analysis;

import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.analysis.classifier.*;
import de.rub.nds.statevulnfinder.core.issue.StateMachineIssue;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class Analyzer {

    private static final Logger LOG = LogManager.getLogger();

    private final GraphDetails graphDetails;

    protected Analyzer(GraphDetails graphDetails) {
        this.graphDetails = graphDetails;
    }

    public abstract List<Classifier> getClassifiers();

    public List<StateMachineIssue> findVulnerabilities(StateMachine machine) {
        List<StateMachineIssue> vulnList = new LinkedList<>();
        ExecutorService classifierExecutor = Executors.newSingleThreadExecutor();
        for (Classifier classifier : getClassifiers()) {
            runClassifier(classifierExecutor, classifier, machine, vulnList);
        }
        classifierExecutor.shutdown();
        graphDetails.setVulnList(vulnList);
        return vulnList;
    }

    private void runClassifier(
            ExecutorService classifierExecutor,
            Classifier classifier,
            StateMachine machine,
            List<StateMachineIssue> vulnList) {
        Future<Object> future =
                classifierExecutor.submit(() -> classifier.getVulnerabilitiesOfClass(machine));
        List<StateMachineIssue> foundVulnerabilities = null;
        try {
            if (machine.getConfig() == null || machine.getConfig().getAnalysisTimeout() == null) {
                foundVulnerabilities = (List<StateMachineIssue>) future.get();
            } else {
                foundVulnerabilities =
                        (List<StateMachineIssue>)
                                future.get(
                                        machine.getConfig().getAnalysisTimeout(),
                                        TimeUnit.MILLISECONDS);
            }

        } catch (IllegalArgumentException | InterruptedException | ExecutionException ex) {
            String identifier =
                    (machine.getConfig() != null)
                            ? machine.getConfig().getImplementationName()
                            : "Unspecified";
            LOG.error(
                    "Cannot run analyzer {} for {}",
                    classifier.getClass().getName(),
                    identifier,
                    ex);
        } catch (TimeoutException ex) {

            if (classifier.getDeterminedVulnerabilities() != null) {
                // salvage results if analysis was interrupted
                foundVulnerabilities = classifier.getDeterminedVulnerabilities();
                LOG.error(
                        "Analyzer {} reached timeout for {}. Until interrupt, {} vulnerabilities have been found.",
                        classifier.getClass().getName(),
                        machine.getConfig().getImplementationName(),
                        foundVulnerabilities.size());
            } else {
                LOG.error(
                        "Analyzer {} reached timeout for {}. No vulnerabilities have been found.",
                        classifier.getClass().getName(),
                        machine.getConfig().getImplementationName());
            }
        } finally {
            future.cancel(true);
            if (foundVulnerabilities != null) {
                vulnList.addAll(foundVulnerabilities);
            }
        }
    }
}
