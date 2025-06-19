/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.sul;

import de.rub.nds.statevulnfinder.core.algorithm.words.GenericMessageWord;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.analysis.utils.SulResponse;
import java.util.*;

public class TimeMeasureSUL implements HintedSUL<TlsWord, SulResponse> {

    private final HintedSUL<TlsWord, SulResponse> delegate;
    private long totalTime = 0;
    private final Map<Class<?>, Long> timePerWord = new HashMap<>();

    public TimeMeasureSUL(HintedSUL<TlsWord, SulResponse> delegate) {
        this.delegate = delegate;
    }

    @Override
    public void pre() {
        delegate.pre();
    }

    @Override
    public void post() {
        delegate.post();
    }

    @Override
    public SulResponse step(TlsWord in) {
        return stepWithHint(in, new ReceiveHint(null));
    }

    private void putOrAdd(Class<?> word, Long time) {
        Long previousTime = this.timePerWord.getOrDefault(word, 0L);
        this.timePerWord.put(word, previousTime + time);
    }

    public String getStatistics() {
        StringBuilder s = new StringBuilder();
        s.append("Total time: ")
                .append((int) (this.totalTime / 1000000000))
                .append(" seconds\n")
                .append("Time by word:\n");
        List<Class<?>> wordList = new LinkedList<>(this.timePerWord.keySet());
        wordList.sort(Comparator.comparing(timePerWord::get));
        for (Class<?> word : wordList) {
            String wordName = word.getSimpleName();
            long time = this.timePerWord.get(word);
            int seconds = (int) (time / 1000000000);
            double percentage = ((int) ((((double) time / totalTime) * 10000))) / 100.0;
            s.append(wordName)
                    .append("(time: ")
                    .append(seconds)
                    .append("s, percentage of total time: ")
                    .append(percentage)
                    .append("%)\n");
        }
        return s.toString();
    }

    @Override
    public SulResponse stepWithHint(TlsWord in, ReceiveHint hint) {
        long startTime = System.nanoTime();
        SulResponse sulResponse = delegate.stepWithHint(in, hint);
        long stopTime = System.nanoTime();
        long totalTime = stopTime - startTime;
        if (in instanceof GenericMessageWord) {
            this.putOrAdd(((GenericMessageWord) in).getMessage().getClass(), totalTime);
        } else {
            this.putOrAdd(in.getClass(), totalTime);
        }
        this.totalTime += totalTime;
        return sulResponse;
    }
}
