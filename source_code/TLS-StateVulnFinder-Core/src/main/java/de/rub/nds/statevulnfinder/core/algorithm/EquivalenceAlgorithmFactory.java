/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.algorithm;

import de.learnlib.api.SUL;
import de.learnlib.api.oracle.EquivalenceOracle;
import de.learnlib.oracle.equivalence.RandomWpMethodEQOracle;
import de.learnlib.oracle.equivalence.WMethodEQOracle;
import de.learnlib.oracle.equivalence.WpMethodEQOracle;
import de.learnlib.oracle.equivalence.mealy.RandomWalkEQOracle;
import de.learnlib.oracle.membership.SULOracle;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.config.VulnerabilityFinderConfig;
import de.rub.nds.statevulnfinder.core.constants.EquivalenceTestAlgorithmName;
import java.util.Random;
import net.automatalib.words.Alphabet;

public class EquivalenceAlgorithmFactory {

    private EquivalenceAlgorithmFactory() {}

    public static EquivalenceOracle getAlgorithm(
            EquivalenceTestAlgorithmName name,
            Alphabet<TlsWord> alphabet,
            SUL<TlsWord, SulResponse> systemUnderTest,
            VulnerabilityFinderConfig config) {
        SULOracle<TlsWord, SulResponse> sulOracle = new SULOracle<>(systemUnderTest);
        switch (name) {
            case VULNERABILITY:
                return new AnalyzerEQOracle(sulOracle, config, alphabet);
            case W_METHOD:
                return new WMethodEQOracle(sulOracle, config.getMaxDepth());
            case RANDOM_WORDS:
                return new CountingRandomWordsEQOracle(
                        sulOracle,
                        config.getMinLength(),
                        config.getMaxLength(),
                        config.getNumberOfQueries(),
                        new Random(0L));
            case RANDOM_WALK:
                return new RandomWalkEQOracle(
                        systemUnderTest, 0, config.getMaxLength(), new Random(0L));
            case WP_METHOD:
                return new WpMethodEQOracle(sulOracle, config.getMaxDepth());
            case RANDOM_WP_METHOD:
                return new RandomWpMethodEQOracle(
                        sulOracle, config.getMinLength(), 5, config.getNumberOfQueries());
            case RANDOM_WORDS_STATE:
                return new StateBoundRandomWordsEQOracle(sulOracle, config, alphabet);
            default:
                throw new UnsupportedOperationException(
                        "Unknown EquivalenceTesting Algorithm"); // TODO change exception
                // type
        }
    }
}
