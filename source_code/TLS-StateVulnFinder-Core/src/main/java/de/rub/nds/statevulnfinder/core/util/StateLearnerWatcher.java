/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.util;

public interface StateLearnerWatcher {
    public void initialize(String targetName);

    public void startScanner(String targetName);

    public void startLearning(String targetName, String alphabet);

    public void connectionUpdate(String targetName, long connectionCount, int activeTimeout);

    public void cacheExceptionUpdate(
            String targetName, long exceptionsOfAlphabet, int activeTimeout, String details);

    public void changePauseStatus(String targetName, boolean paused);

    public void eventReached(String targetName, String event);

    public boolean killTask(String targetName);
}
