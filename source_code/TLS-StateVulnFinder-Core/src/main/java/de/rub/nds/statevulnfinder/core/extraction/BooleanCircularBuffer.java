/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.extraction;

/**
 * @author marcel
 */
public class BooleanCircularBuffer {
    private final boolean[] buffer;
    private int head;
    private int size;

    private int trueListed = 0;

    public BooleanCircularBuffer(int capacity) {
        buffer = new boolean[capacity];
        head = 0;
        size = 0;
    }

    // Add a new boolean value to the buffer
    public void add(boolean value) {
        if (size < buffer.length && value) {
            trueListed += 1;
        } else if (buffer[head] != value) {
            if (value) {
                trueListed += 1;
            } else {
                trueListed -= 1;
            }
        }
        buffer[head] = value;
        head = (head + 1) % buffer.length;
        if (size < buffer.length) {
            size++;
        }
    }

    // Get the value at a specific index
    public boolean get(int index) {
        if (index < 0 || index >= size) {
            throw new IndexOutOfBoundsException("Index out of bounds: " + index);
        }
        int effectiveIndex = (head - size + index + buffer.length) % buffer.length;
        return buffer[effectiveIndex];
    }

    // Get the current size of the buffer
    public int size() {
        return size;
    }

    // Check if the buffer is full
    public boolean isFull() {
        return size == buffer.length;
    }

    public int getTrueListed() {
        return trueListed;
    }

    public void clearOldestConflict() {
        for (int i = 0; i < size; i++) {
            int index = (head + i) % buffer.length;
            if (buffer[index]) {
                buffer[index] = false;
                trueListed--;
                return;
            }
        }
    }
}
