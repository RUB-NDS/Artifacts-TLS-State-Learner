/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.server.analysis;

import de.rub.nds.statevulnfinder.core.analysis.Analyzer;
import de.rub.nds.statevulnfinder.core.analysis.GraphDetails;
import de.rub.nds.statevulnfinder.core.analysis.classifier.BenignSubgraphClassifier;
import de.rub.nds.statevulnfinder.core.analysis.classifier.BleichenbacherOracleClassifier;
import de.rub.nds.statevulnfinder.core.analysis.classifier.CCSClassifier;
import de.rub.nds.statevulnfinder.core.analysis.classifier.Classifier;
import de.rub.nds.statevulnfinder.core.analysis.classifier.ErrorStateClassifier;
import de.rub.nds.statevulnfinder.core.analysis.classifier.IllegalTransitionClassifier;
import de.rub.nds.statevulnfinder.core.analysis.classifier.PaddingOracleClassifier;
import de.rub.nds.statevulnfinder.core.analysis.classifier.ResponseClassifier;
import de.rub.nds.statevulnfinder.core.analysis.classifier.subclassifier.InternalErrorSubclassifier;
import de.rub.nds.statevulnfinder.core.analysis.classifier.subclassifier.KeyblockLeakSubclassifier;
import de.rub.nds.statevulnfinder.core.analysis.classifier.subclassifier.UnknownMessageSubclassifier;
import de.rub.nds.statevulnfinder.server.analysis.transition.ServerTransitionAnalyzerProvider;
import java.util.LinkedList;
import java.util.List;

public class ServerAnalyzer extends Analyzer {

    private final List<Classifier> classifiers;

    public ServerAnalyzer(GraphDetails graphDetails) {
        super(graphDetails);
        ServerTransitionAnalyzerProvider transitionAnalyzer =
                new ServerTransitionAnalyzerProvider();
        classifiers = new LinkedList<>();
        classifiers.add(new ErrorStateClassifier(graphDetails));
        classifiers.add(new BenignSubgraphClassifier(graphDetails, transitionAnalyzer));
        classifiers.add(new IllegalTransitionClassifier(graphDetails, transitionAnalyzer));
        classifiers.add(new BleichenbacherOracleClassifier(graphDetails));
        classifiers.add(new PaddingOracleClassifier(graphDetails));
        classifiers.add(new CCSClassifier(graphDetails));
        classifiers.add(
                new ResponseClassifier(
                        graphDetails,
                        transitionAnalyzer,
                        new InternalErrorSubclassifier(),
                        new KeyblockLeakSubclassifier(),
                        new UnknownMessageSubclassifier()));
    }

    @Override
    public List<Classifier> getClassifiers() {
        return classifiers;
    }
}
