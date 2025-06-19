/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.analysis.utils;

import de.rub.nds.tlsattacker.core.layer.Message;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Wraps a ResponseFingerprint so we can reliably differ between an actual response and an illegal
 * learner transition
 */
public class SulResponse {

    public static SulResponse ILLEGAL_LEARNER_TRANSITION = new SulResponse(true);

    private boolean illegalTransitionFlag;

    private ResponseFingerprint responseFingerprint;

    public SulResponse() {}

    public SulResponse(ResponseFingerprint responseFingerprint) {
        this.responseFingerprint = responseFingerprint;
        this.illegalTransitionFlag = false;
    }

    public SulResponse(boolean illegalTransitionFlag) {
        this(new ResponseFingerprint());
        this.illegalTransitionFlag = illegalTransitionFlag;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final SulResponse other = (SulResponse) obj;
        if (other.isIllegalTransitionFlag() != this.isIllegalTransitionFlag()) {
            return false;
        }
        if (!this.isIllegalTransitionFlag()
                && !this.getResponseFingerprint().equals(other.getResponseFingerprint())) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 79 * hash + (this.illegalTransitionFlag ? 1 : 0);
        if (!illegalTransitionFlag) {
            hash = 79 * hash + Objects.hashCode(this.responseFingerprint);
        }
        return hash;
    }

    @Override
    public String toString() {
        if (illegalTransitionFlag) {
            return "IllegalTransition";
        }
        return responseFingerprint.toString();
    }

    public String toShortString() {
        if (illegalTransitionFlag) {
            return toString();
        }
        return responseFingerprint.toShortString();
    }

    public boolean isIllegalTransitionFlag() {
        return illegalTransitionFlag;
    }

    public void setIllegalTransitionFlag(boolean illegalTransitionFlag) {
        this.illegalTransitionFlag = illegalTransitionFlag;
    }

    public ResponseFingerprint getResponseFingerprint() {
        return responseFingerprint;
    }

    public void setResponseFingerprint(ResponseFingerprint responseFingerprint) {
        this.responseFingerprint = responseFingerprint;
    }

    public boolean hasMessages() {
        return !(this.isIllegalTransitionFlag()
                || this.getResponseFingerprint() == null
                || this.getResponseFingerprint().getRecordList() == null
                || this.getResponseFingerprint().getRecordList().isEmpty()
                || this.getResponseFingerprint().getMessageList() == null
                || this.getResponseFingerprint().getMessageList().isEmpty());
    }

    public boolean responseContainsMessage(Class<?> expectedMessageClass) {
        if (!hasMessages()) {
            return false;
        }
        return this.getResponseFingerprint().getMessageList().stream()
                .anyMatch(message -> message.getClass().equals(expectedMessageClass));
    }

    public boolean responseContainsMessagesOtherThan(Class<?>... expectedMessageClasses) {
        if (!hasMessages()) {
            return false;
        }
        List<Class<?>> expectedMessageClassesList = Arrays.asList(expectedMessageClasses);
        Set<Class<? extends Message>> presentClasses =
                this.getResponseFingerprint().getMessageList().stream()
                        .map(Message::getClass)
                        .collect(Collectors.toSet());
        presentClasses.removeAll(expectedMessageClassesList);
        return !presentClasses.isEmpty();
    }
}
