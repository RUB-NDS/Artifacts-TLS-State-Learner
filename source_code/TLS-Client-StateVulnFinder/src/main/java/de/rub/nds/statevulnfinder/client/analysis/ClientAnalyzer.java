/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.client.analysis;

import de.rub.nds.statevulnfinder.client.analysis.transition.ClientTransitionAnalyzerProvider;
import de.rub.nds.statevulnfinder.core.analysis.Analyzer;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.analysis.classifier.BenignSubgraphClassifier;
import de.rub.nds.statevulnfinder.core.analysis.classifier.Classifier;
import de.rub.nds.statevulnfinder.core.analysis.classifier.ErrorStateClassifier;
import de.rub.nds.statevulnfinder.core.analysis.classifier.IllegalTransitionClassifier;
import java.util.LinkedList;
import java.util.List;

/**
 * @author marcel
 */
public class ClientAnalyzer extends Analyzer {

    private final List<Classifier> classifiers;

    public ClientAnalyzer(GraphDetails graphDetails) {
        super(graphDetails);
        ClientTransitionAnalyzerProvider transitionAnalyzerProvider =
                new ClientTransitionAnalyzerProvider();
        classifiers = new LinkedList<>();
        classifiers.add(new ErrorStateClassifier(graphDetails));
        classifiers.add(new BenignSubgraphClassifier(graphDetails, transitionAnalyzerProvider));
        classifiers.add(new IllegalTransitionClassifier(graphDetails, transitionAnalyzerProvider));
        // classifiers.add(new PaddingOracleClassifier(graphDetails));
        // classifiers.add(new ResponseClassifier(graphDetails, transitionAnalyzerProvider,
        // new InternalErrorSubclassifier(), new UnknownMessageSubclassifier()));
    }

    @Override
    public List<Classifier> getClassifiers() {
        return classifiers;
    }
}
