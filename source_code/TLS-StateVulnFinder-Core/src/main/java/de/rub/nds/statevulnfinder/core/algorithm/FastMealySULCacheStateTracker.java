/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.algorithm;

import de.rub.nds.statevulnfinder.core.algorithm.words.BleichenbacherWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.ChangeCipherSpecWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.ClientKeyExchangeWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.PaddingOracleWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.ResetConnectionWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.ResumingClientHelloWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import net.automatalib.words.Word;
import net.automatalib.words.WordBuilder;

public class FastMealySULCacheStateTracker {
    // reached dead end with cache
    private boolean reachedDeadEndWithCache;

    public void setReachedDeadEndWithCache(boolean reachedDeadEndWithCache) {
        this.reachedDeadEndWithCache = reachedDeadEndWithCache;
    }

    public boolean isReachedDeadEndWithCache() {
        return reachedDeadEndWithCache;
    }

    // whether we already sent a CCS message
    private boolean sawCCS;
    // whether the last sent key exchange message was an rsa key exchange
    private boolean rsaKexCipherSuiteNegotiatedLast;
    // if true, the oracle answers all queries as if the server went into the illegal transition
    // state
    private boolean simulateError;

    public boolean isSimulateError() {
        return simulateError;
    }

    public void setSimulateError(boolean simulateError) {
        this.simulateError = simulateError;
    }

    private boolean resetLast;
    private boolean updateCache;
    private boolean filterApplied;
    private boolean uninterestingFilterApplied;

    public boolean isUninterestingFilterApplied() {
        return uninterestingFilterApplied;
    }

    public boolean isFilterApplied() {
        return filterApplied;
    }

    public void setUpdateCache() {
        updateCache = true;
    }

    public boolean isUpdateCache() {
        return updateCache;
    }

    private boolean sawCKE;
    private boolean receivedTicket;

    public FastMealySULCacheStateTracker() {}

    public void reset() {
        sawCCS = false;
        rsaKexCipherSuiteNegotiatedLast = false;
        simulateError = false;
        resetLast = false;
        updateCache = false;
        sawCKE = false;
        receivedTicket = false;
        reachedDeadEndWithCache = false;
        filterApplied = false;
        uninterestingFilterApplied = false;
    }

    public boolean wordCanBeFiltered(
            TlsWord in, WordBuilder<SulResponse> outputWord, boolean fastCache) {
        if (simulateError || filterApplies(in, outputWord, fastCache)) {
            filterApplied = true;
            simulateError = true;
            return true;
        } else {
            return false;
        }
    }

    public boolean filterApplies(
            TlsWord in, WordBuilder<SulResponse> outputWord, boolean fastCache) {
        if (resetFilterApplies(in, outputWord)
                || resumptionFilterApplies(in)
                || postResetFilterApplies(in)
                || (fastCache && attackFilterApplies(in))) {
            uninterestingFilterApplied = true;
            return true;
        }
        return false;
    }

    public boolean attackFilterApplies(TlsWord in) {
        if (in instanceof BleichenbacherWord && !rsaKexCipherSuiteNegotiatedLast) {
            // we only allow bb words if the last message was an RSA hello
            return true;
        } else if (in instanceof PaddingOracleWord && !sawCCS) {
            // we only allow po words if there has been a CCS message
            return true;
        } else {
            return false;
        }
    }

    /**
     * Determines if we would reset twice or reset at the start.
     *
     * @param in the potential next input from the alphabet
     * @return true if filter applies, false otherwise
     */
    public boolean resetFilterApplies(TlsWord in, WordBuilder<SulResponse> outputWord) {
        return (in instanceof ResetConnectionWord && resetLast)
                || (in instanceof ResetConnectionWord && outputWord.isEmpty());
    }

    /**
     * Determines if we build a flow containing a reset that does not benefit from the reset.
     * Specifically, any regular ClientHello sent immediately after the reset except for a
     * ResumingHello. Since we clear all saved sessions upon a full handshake (and therefore
     * anything we might obtain from a reset session) there is no advantage compared to testing the
     * sequence immediately in the first session.
     *
     * @param in the potential next input from the alphabet
     * @return true if filter applies, false otherwise
     */
    public boolean postResetFilterApplies(TlsWord in) {
        return (resetLast
                && in.getType().isAnyClientHello()
                && in.getType() != TlsWordType.HRR_ENFORCING_HELLO
                && in.getType() != TlsWordType.RESUMING_HELLO);
    }

    public boolean resumptionFilterApplies(TlsWord in) {
        if (in instanceof ResumingClientHelloWord) {
            ResumingClientHelloWord resumingHello = (ResumingClientHelloWord) in;
            if ((resumingHello.getResumptionType() == ResumingClientHelloWord.ResumptionType.TICKET
                            || resumingHello.getResumptionType()
                                    == ResumingClientHelloWord.ResumptionType.TLS_1_3_TICKET)
                    && !receivedTicket) {
                // resumption impossible, no ticket present
                return true;
            } else if (resumingHello.getResumptionType()
                            == ResumingClientHelloWord.ResumptionType.ID
                    && !sawCKE) {
                // resumption impossible, no session present
                return true;
            }
        }
        return false;
    }

    public void updateWordFilter(TlsWord in, SulResponse out) {
        if (out.isIllegalTransitionFlag()) {
            simulateError = true;
        }

        // experimental: we no check if an rsa cipher suite was **negotiated** last
        // when only checking if a TLS_RSA ch was sent last, we would create invalid state
        // transitions (as described in the comment that was formerly here)
        if (rsaCipherSuiteNegotiated(in, out)) {
            rsaKexCipherSuiteNegotiatedLast = true;
        }

        // connection reset was last
        resetLast = in instanceof ResetConnectionWord;
        // CCS in any of the last messages
        sawCCS |= in instanceof ChangeCipherSpecWord;
        if (in instanceof ResetConnectionWord) {
            sawCCS = false;
            rsaKexCipherSuiteNegotiatedLast = false;
        }
        sawCKE |= in instanceof ClientKeyExchangeWord;
        receivedTicket |=
                !out.isIllegalTransitionFlag()
                        && out.getResponseFingerprint().getMessageList().stream()
                                .anyMatch(NewSessionTicketMessage.class::isInstance);
    }

    /**
     * We want to restric RsaClientKeyExchange messages to TLS_RSA cipher suites to prevent parsing
     * errors that happen by chance when the peer does not expect RSA encrypted CKEs. We use the
     * negotiated state to prevent faulty analysis results caused by rejected renegotiation
     * attempts.
     *
     * @return
     */
    public boolean rsaCipherSuiteNegotiated(TlsWord in, SulResponse out) {
        return in.getType().isAnyClientHello()
                && out.getResponseFingerprint() != null
                && out.getResponseFingerprint().getMessageList() != null
                && out.getResponseFingerprint().getMessageList().stream()
                        .anyMatch(ServerHelloMessage.class::isInstance)
                && CipherSuite.getCipherSuite(
                                out.getResponseFingerprint().getMessageList().stream()
                                        .filter(ServerHelloMessage.class::isInstance)
                                        .map(message -> (ServerHelloMessage) message)
                                        .findFirst()
                                        .get()
                                        .getSelectedCipherSuite()
                                        .getValue())
                        .name()
                        .contains("TLS_RSA");
    }

    public Word<SulResponse> applyCacheFiltersToInputOutputPair(
            Word<TlsWord> input, Word<SulResponse> outputWord) {
        WordBuilder<SulResponse> filteredOutputWord = new WordBuilder<>();
        for (int i = 0; i < input.size(); i++) {
            if (wordCanBeFiltered(input.getSymbol(i), filteredOutputWord, true)) {
                filteredOutputWord.add(SulResponse.ILLEGAL_LEARNER_TRANSITION);
            } else {
                filteredOutputWord.add(outputWord.getSymbol(i));
            }
            updateWordFilter(input.getSymbol(i), filteredOutputWord.getSymbol(i));
        }
        return filteredOutputWord.toWord();
    }
}
