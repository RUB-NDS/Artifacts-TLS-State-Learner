/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.algorithm;

import de.learnlib.acex.analyzers.AcexAnalyzers;
import de.learnlib.algorithms.dhc.mealy.MealyDHC;
import de.learnlib.algorithms.kv.mealy.KearnsVaziraniMealy;
import de.learnlib.algorithms.lstar.mealy.ExtensibleLStarMealyBuilder;
import de.learnlib.algorithms.malerpnueli.MalerPnueliMealy;
import de.learnlib.algorithms.rivestschapire.RivestSchapireMealy;
import de.learnlib.algorithms.ttt.mealy.TTTLearnerMealy;
import de.learnlib.api.SUL;
import de.learnlib.api.algorithm.LearningAlgorithm;
import de.learnlib.api.oracle.MembershipOracle;
import de.learnlib.oracle.membership.SULOracle;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.constants.LearningAlgorithmName;
import net.automatalib.words.Alphabet;

public class LearningAlgorithmFactory {

    private LearningAlgorithmFactory() {}

    public static LearningAlgorithm getAlgorithm(
            LearningAlgorithmName name,
            Alphabet<TlsWord> alphabet,
            SUL<TlsWord, SulResponse> systemUnderTest) {

        MembershipOracle.MealyMembershipOracle<TlsWord, SulResponse> sulOracle =
                new SULOracle<>(systemUnderTest);
        switch (name) {
            case DHC:
                return new MealyDHC<>(alphabet, sulOracle);
            case KV:
                return new KearnsVaziraniMealy<>(
                        alphabet, sulOracle, true, AcexAnalyzers.BINARY_SEARCH_FWD);
            case LSTAR:
                return new ExtensibleLStarMealyBuilder()
                        .withAlphabet(alphabet)
                        .withOracle(sulOracle)
                        .create();
            case MP:
                return new MalerPnueliMealy<>(alphabet, sulOracle);
            case RS:
                return new RivestSchapireMealy<>(alphabet, sulOracle);
            case TTT:
                return new TTTLearnerMealy<>(alphabet, sulOracle, AcexAnalyzers.BINARY_SEARCH_FWD);
            default:
                throw new UnsupportedOperationException(
                        "Unknown LearningAlgorithm"); // TODO change exception type
        }
    }
}
