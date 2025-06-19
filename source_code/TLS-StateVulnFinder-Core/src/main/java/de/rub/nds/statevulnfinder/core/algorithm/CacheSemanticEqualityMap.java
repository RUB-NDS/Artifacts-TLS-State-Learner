/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.algorithm;

import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.tlsscanner.core.vector.response.EqualityError;
import de.rub.nds.tlsscanner.core.vector.response.FingerprintChecker;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

public class CacheSemanticEqualityMap {
    private HashMap<Integer, List<SulResponse>> semanticResponseMap = new HashMap<>();

    public SulResponse getSemanticEquivalent(SulResponse response) {
        if (true) {
            return response;
        }
        if (response.isIllegalTransitionFlag()) {
            return SulResponse.ILLEGAL_LEARNER_TRANSITION;
        }
        int recordCount = response.getResponseFingerprint().getRecordList().size();
        semanticResponseMap.putIfAbsent(recordCount, new LinkedList<>());
        for (SulResponse storedResponse : semanticResponseMap.get(recordCount)) {
            if (FingerprintChecker.checkEquality(
                            storedResponse.getResponseFingerprint(),
                            response.getResponseFingerprint())
                    == EqualityError.NONE) {
                return storedResponse;
            }
        }
        semanticResponseMap.get(recordCount).add(response);
        return response;
    }
}
