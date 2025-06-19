/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.algorithm;

import com.google.common.base.Objects;
import de.learnlib.api.SUL;
import de.rub.nds.statevulnfinder.core.algorithm.words.*;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import de.rub.nds.statevulnfinder.core.config.VulnerabilityFinderConfig;
import de.rub.nds.statevulnfinder.core.extraction.TLSConflictException;
import de.rub.nds.statevulnfinder.core.extraction.TimeoutHandler;
import de.rub.nds.statevulnfinder.core.sul.HintedSUL;
import de.rub.nds.statevulnfinder.core.sul.ReceiveHint;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.stream.Collectors;
import net.automatalib.automata.transducers.impl.FastMealy;
import net.automatalib.automata.transducers.impl.FastMealyState;
import net.automatalib.automata.transducers.impl.MealyTransition;
import net.automatalib.words.Alphabet;
import net.automatalib.words.Word;
import net.automatalib.words.WordBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Caches queries made to a TLSSul. Very similar to and borrows a lot of code from the
 * AbstractSULCacheImpl class of the automatalib. We don't extend that class because the automatalib
 * does not grant access to a lot of internal classes. Also has the possibility to filter out PO and
 * BB messages that do not make sense to send.
 */
public class FastMealySULCache implements SUL<TlsWord, SulResponse> {
    private static final Logger LOG = LogManager.getLogger();

    // The underlying systemUnderLearning which is queried when the oracle cannot answer a query.
    HintedSUL<TlsWord, SulResponse> delegate;
    Alphabet<TlsWord> alphabet;
    // A Mealy automaton/graph which holds our cache
    FastMealy<TlsWord, SulResponse> cacheGraph;

    ReadWriteLock lock;

    private final WordBuilder<TlsWord> inputWord = new WordBuilder<>();
    private final WordBuilder<SulResponse> outputWord = new WordBuilder<>();

    private boolean fastCache;

    // true after the cache has a miss
    private boolean usingDelegate;
    // true if we called the pre() method of our delegate
    private boolean delegatePreCalled;
    // we have to save our current state between different calls of step()
    protected FastMealyState<SulResponse> current;

    private boolean trappedAfterIllegalTransition = false;

    private VulnerabilityFinderConfig finderConfig;

    private final FastMealySULCacheStateTracker cacheStateTracker =
            new FastMealySULCacheStateTracker();

    private final CacheSemanticEqualityMap cacheSemanticEqualityMap =
            new CacheSemanticEqualityMap();

    private TimeoutHandler timeoutHandler;

    private long filterCachedWords;
    private long uninterestingCachedWords;
    private long fullyChachedWords;
    private long uncachedWords;
    private long fullyCachedSymbols;
    SulResponse errorResponse = new SulResponse(true);

    public FastMealySULCache(
            HintedSUL<TlsWord, SulResponse> delegate,
            Alphabet<TlsWord> alphabet,
            ReadWriteLock lock,
            boolean fastCache,
            TimeoutHandler timeoutHandler,
            VulnerabilityFinderConfig finderConfig) {
        super();
        this.timeoutHandler = timeoutHandler;
        this.delegate = delegate;
        this.alphabet = alphabet;
        this.cacheGraph = new FastMealy<>(alphabet);
        cacheGraph.setInitialState(cacheGraph.addState());
        this.lock = lock;
        this.finderConfig = finderConfig;
        /*
         * if true, uninteresting Bleichenbacher and Padding Oracle words are not delegated to the underlying SUL/T.
         * Speedup of roughly x4.
         */
        this.fastCache = fastCache;
    }

    @Override
    public void pre() {
        // reset everything and acquire read lock
        lock.readLock().lock();
        this.current = cacheGraph.getInitialState();
        this.usingDelegate = false;
        cacheStateTracker.reset();
        this.trappedAfterIllegalTransition = false;
    }

    @Override
    public void post() {
        TLSConflictException tlsConflictException = null;
        // release all locks and clean up buffers, update cache if we have to
        if (!cacheStateTracker.isUpdateCache() || cacheStateTracker.isReachedDeadEndWithCache()) {
            // if outputWord is empty we still hold the read-lock!
            try {
                lock.readLock().unlock();
            } catch (Exception ignored) {
                // interruption by exception unlocks
            }
        } else {
            // in this case we have to update our cacheGraph
            lock.writeLock().lock();
            try {
                insert(inputWord.toWord(), outputWord.toWord());
            } catch (TLSConflictException e) {
                // save for later
                tlsConflictException = e;
            }
            lock.writeLock().unlock();
        }

        if (delegatePreCalled) {
            delegate.post();
            delegatePreCalled = false;
            uncachedWords++;
        } else {
            fullyChachedWords++;
            if (cacheStateTracker.isUninterestingFilterApplied()) {
                uninterestingCachedWords++;
            } else if (cacheStateTracker.isFilterApplied() || trappedAfterIllegalTransition) {
                filterCachedWords++;
            }
            fullyCachedSymbols += inputWord.size();
        }
        inputWord.clear();
        outputWord.clear();
        if (tlsConflictException != null) {
            throw tlsConflictException;
        }
    }

    @Override
    public SulResponse step(TlsWord in) {
        SulResponse out = null;
        // we always query the cache first
        if (!usingDelegate) {
            MealyTransition<FastMealyState<SulResponse>, SulResponse> trans =
                    cacheGraph.getTransition(current, in);

            if (finderConfig.isDisableCache()) {
                // artifically disable the cache
                trans = null;
            }

            if (trans != null && !cacheStateTracker.isUpdateCache()) {
                // on a cache hit: use the cache's result
                out = cacheGraph.getTransitionOutput(trans);
                current = cacheGraph.getSuccessor(trans);
                assert current != null;
                if (out.isIllegalTransitionFlag()) {
                    cacheStateTracker.setSimulateError(true);
                }
            } else if (!cacheStateTracker.isSimulateError()
                    || (finderConfig.isNoCacheTrapping() && !cacheStateTracker.isUpdateCache())) {
                // on a cache miss: query all answered queries with our delegate to prepare our
                // cache update
                lock.readLock().unlock();
                if (cacheStateTracker.wordCanBeFiltered(in, outputWord, fastCache)
                        && !finderConfig.isNoCacheTrapping()) {
                    // we cached all transitions so far and next word would lead to
                    // IllegalLearnerState
                    out = errorResponse;
                } else {
                    // we must send all previous inputs with delegate
                    queryDelegateForPreviousSymbols();
                }
                cacheStateTracker.setUpdateCache();
            } else {
                trappedAfterIllegalTransition = true;
                if (!cacheStateTracker.isUpdateCache()) {
                    lock.readLock().unlock();
                }
                // we haven't cached the transition but we know we are trapped
                out = errorResponse;
                cacheStateTracker.setUpdateCache();
            }
        }

        inputWord.append(in);
        if (usingDelegate) {
            if (cacheStateTracker.wordCanBeFiltered(in, outputWord, fastCache)
                    && !finderConfig.isNoCacheTrapping()) {
                out = errorResponse;
            } else {
                try {
                    // at this point we do not know what to expect
                    out = delegate.stepWithHint(in, new ReceiveHint(null));
                } catch (Exception ex) {
                    LOG.error(
                            "Delegate query failed for input {} ({})",
                            in.getType(),
                            in.toString(),
                            ex);
                    throw ex;
                }
            }
        }
        outputWord.add(out);
        cacheStateTracker.updateWordFilter(in, out);

        return out;
    }

    private void queryDelegateForPreviousSymbols() {
        usingDelegate = true;
        requiredInitializedDelegate();
        List<SulResponse> expectedResponsesForPrevious = outputWord.toWord().asList();
        Iterator<SulResponse> expectedResponseIterator = expectedResponsesForPrevious.iterator();
        outputWord.clear();

        cacheStateTracker.reset();
        for (TlsWord prevSym : inputWord) {
            SulResponse prevOut;
            if (cacheStateTracker.wordCanBeFiltered(prevSym, outputWord, fastCache)
                    && !finderConfig.isNoCacheTrapping()) {
                prevOut = errorResponse;
            } else {
                ResponseFingerprint expectedResponseFingerprint =
                        expectedResponseIterator.next().getResponseFingerprint();
                ReceiveHint receiveHint =
                        new ReceiveHint(
                                expectedResponseFingerprint.getMessageList(),
                                expectedResponseFingerprint.getSocketState());
                prevOut = delegate.stepWithHint(prevSym, receiveHint);
            }
            outputWord.add(prevOut);
            cacheStateTracker.updateWordFilter(prevSym, prevOut);
        }
    }

    protected void requiredInitializedDelegate() {
        // only call pre() of delegate once but do it
        if (!delegatePreCalled) {
            delegate.pre();
        }
        delegatePreCalled = true;
    }

    public void insert(Word<TlsWord> input, Word<SulResponse> outputWord)
            throws TLSConflictException {
        insert_inner(input, outputWord, false);
    }

    public void overwrite(Word<TlsWord> input, Word<SulResponse> outputWord)
            throws TLSConflictException {
        insert_inner(input, outputWord, true);
    }

    /**
     * Inserts a new input-output combination into the cache graph.
     *
     * @param input The input to consider.
     * @param outputWord The output to consider.
     * @param overwrite If true, any differing occurrences with the same input are overwritten. If
     *     false, an exception is thrown.
     */
    public void insert_inner(Word<TlsWord> input, Word<SulResponse> outputWord, boolean overwrite)
            throws TLSConflictException {
        // insert the combination of input and output into our cache
        // hols information about the path we walked so far
        WordBuilder<SulResponse> wordBuilder = new WordBuilder<>();
        FastMealyState<SulResponse> curr = cacheGraph.getInitialState();
        if (finderConfig.isDisableCache()) {
            return;
        }

        Iterator<? extends SulResponse> outputIt = outputWord.iterator();
        for (TlsWord sym : input) {
            SulResponse out = outputIt.next();
            out = reduceResponseFingerprint(out);
            MealyTransition<FastMealyState<SulResponse>, SulResponse> trans =
                    cacheGraph.getTransition(curr, sym);
            if (trans == null) {
                // from here the cache has a miss and we, therefore, update it with a new node

                FastMealyState<SulResponse> fastMealyState = cacheGraph.addState();

                cacheGraph.setTransition(
                        curr,
                        sym,
                        fastMealyState,
                        cacheSemanticEqualityMap.getSemanticEquivalent(out));
                curr = fastMealyState;
                if (out.isIllegalTransitionFlag()) {
                    // don't add chain of dead states
                    break;
                }
            } else if (Objects.equal(out, trans.getOutput())) {
                // there is no conflict in the information present and the information given
                curr = trans.getSuccessor();
                // tell the timeout handler that we observed a consistent reaction
                timeoutHandler.knownPrefixQueried(false);
            } else if (overwrite) {
                // we have conflicting information and overwrite our current information with the
                // given information
                FastMealyState<SulResponse> fastMealyState = cacheGraph.addState();

                cacheGraph.removeState(trans.getSuccessor());
                cacheGraph.setTransition(
                        curr,
                        sym,
                        fastMealyState,
                        cacheSemanticEqualityMap.getSemanticEquivalent(out));
                curr = fastMealyState;
            } else {
                // tell the timeout handler that we observed an inconsistent reaction
                timeoutHandler.knownPrefixQueried(true);
                throw new TLSConflictException(
                        input, wordBuilder.append(trans.getOutput()).toWord(), outputWord);
            }
            wordBuilder.append(out);
        }
        if (overwrite && cacheGraph.size() < 50000) {
            // clearOrphanedStates();
        }
    }

    /**
     * When removing states from the cache after a cache conflict, subsequent states remain. Due to
     * the way the cache is traversed, we will never be able to profit from these states. Hence, we
     * can remove them to reduce the RAM footprint.
     */
    private void clearOrphanedStates() {
        int clearedStates = 0;
        do {
            clearedStates = 0;
            Set<FastMealyState> reachableStates = new HashSet();
            for (FastMealyState state : cacheGraph.getStates()) {
                for (TlsWord letter : alphabet) {
                    MealyTransition<FastMealyState<SulResponse>, SulResponse> trans =
                            cacheGraph.getTransition(state, letter);
                    if (trans != null) {
                        reachableStates.add(trans.getSuccessor());
                    }
                }
            }
            Set<FastMealyState> orphanedStates =
                    cacheGraph.getStates().stream()
                            .filter(state -> !reachableStates.contains(state))
                            .collect(Collectors.toSet());
            for (FastMealyState orpahendState : orphanedStates) {
                if (orpahendState != cacheGraph.getInitialState()) {
                    cacheGraph.removeState(orpahendState);
                    clearedStates++;
                }
            }
        } while (clearedStates > 0);
    }

    private SulResponse reduceResponseFingerprint(SulResponse output) {
        if (!output.isIllegalTransitionFlag()) {
            if (output.getResponseFingerprint().getRecordList() != null) {
                for (Record tlsRecord : output.getResponseFingerprint().getRecordList()) {
                    // subset of completeRecordBytes
                    tlsRecord.setProtocolMessageBytes(new byte[0]);
                    if (tlsRecord.getComputations() != null) {
                        // subset of clean protocol message bytes + computation fields
                        tlsRecord.getComputations().setPlainRecordBytes(new byte[0]);
                        // subset of completeRecordBytes
                        tlsRecord.getComputations().setCiphertext(new byte[0]);
                    }
                }
            }
            if (output.getResponseFingerprint().getMessageList() != null) {
                for (ProtocolMessage message : output.getResponseFingerprint().getMessageList()) {
                    if (message.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
                        // subset of completeResultingMessage
                        ((HandshakeMessage) message).setMessageContent(new byte[0]);
                        if (message instanceof CertificateMessage) {
                            // subset of completeResultingMessage
                            ((CertificateMessage) message).setCertificatesListBytes(new byte[0]);
                        }
                    }
                }
            }
            return output;
        } else {
            return SulResponse.ILLEGAL_LEARNER_TRANSITION;
        }
    }

    public long getFilterCachedWords() {
        return filterCachedWords;
    }

    public long getFullyChachedWords() {
        return fullyChachedWords;
    }

    public long getUncachedWords() {
        return uncachedWords;
    }

    public long getFullyCachedSymbols() {
        return fullyCachedSymbols;
    }

    public long getUninterestingCachedWords() {
        return uninterestingCachedWords;
    }
}
