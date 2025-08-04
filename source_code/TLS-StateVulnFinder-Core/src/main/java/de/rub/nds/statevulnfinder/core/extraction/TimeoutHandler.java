/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.extraction;

import de.rub.nds.statevulnfinder.core.config.VulnerabilityFinderConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TimeoutHandler {

    private static final Logger LOG = LogManager.getLogger();
    private static final int FAST_INCREASE_TIMEOUT_CAP = 250;
    private static final int LETTERS_TO_IGNORE_AFTER_INCREASE = 100;

    private final VulnerabilityFinderConfig finderConfig;
    private final BooleanCircularBuffer queriesIssued =
            new BooleanCircularBuffer(LETTERS_TO_IGNORE_AFTER_INCREASE * 2);
    private int timeoutSuggestions = 0;
    private int increasedTimes = 0;

    private int queriedPrefixLettersSinceIncrease = 0;

    public TimeoutHandler(VulnerabilityFinderConfig finderConfig) {
        this.finderConfig = finderConfig;
    }

    public void knownPrefixQueried(boolean cacheException) {
        queriedPrefixLettersSinceIncrease += 1;

        // we deliberately ignore possible cache exceptions after a TO increase to account for
        // multiple previously incorrectly assessed queries
        if (queriedPrefixLettersSinceIncrease > LETTERS_TO_IGNORE_AFTER_INCREASE) {
            queriesIssued.add(cacheException);
            if (cacheException) {
                if (queriesIssued.getTrueListed() >= 2) {
                    suggestIncreasedTimeout();
                    queriesIssued.clearOldestConflict();
                }
            }
            if (queriesIssued.isFull()
                    && queriesIssued.getTrueListed() == 0
                    && timeoutSuggestions > 0) {
                // allow suggestions to heal if conflicts are infrequent
                timeoutSuggestions -= 1;
            }
        } else {
            queriesIssued.add(false);
        }
    }

    public void suggestIncreasedTimeout() {
        timeoutSuggestions++;
        if (finderConfig.getMinTimeout() <= FAST_INCREASE_TIMEOUT_CAP) {

            if (timeoutSuggestions > (2 + increasedTimes)) {
                increaseTimeout();
            }
        } else {
            if (timeoutSuggestions
                    > ((finderConfig.getMinTimeout() - FAST_INCREASE_TIMEOUT_CAP) / 100) * 25) {
                increaseTimeout();
            }
        }
    }

    private void increaseTimeout() {
        if (finderConfig.getMinTimeout() < finderConfig.getMaxTimeout()) {
            int currentTimeout = finderConfig.getMinTimeout();
            finderConfig.setMinTimeout(finderConfig.getMinTimeout() + 10);
            LOG.info(
                    "Increased timeout from {} to {} for {}",
                    currentTimeout,
                    finderConfig.getMinTimeout(),
                    finderConfig.getImplementationName());
            queriedPrefixLettersSinceIncrease = 0;
            increasedTimes++;
        }
        timeoutSuggestions = 0;
    }
}
