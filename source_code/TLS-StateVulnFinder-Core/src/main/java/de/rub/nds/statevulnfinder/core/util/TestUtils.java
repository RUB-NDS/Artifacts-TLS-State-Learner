/*
 * TLS-StateBulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2022 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.util;

import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.xml.MealySerializationHelper;
import java.io.FileInputStream;
import java.io.IOException;
import org.junit.Assert;

public class TestUtils {
    public static StateMachine loadStateMachine(String file) {
        FileInputStream inputStream = null;
        StateMachine stateMachine = null;
        try {
            inputStream = new FileInputStream(file);
            stateMachine = MealySerializationHelper.deserialize(inputStream, null);
        } catch (IOException ex) {
            Assert.fail();
        } finally {
            try {
                inputStream.close();
            } catch (IOException ex) {
                Assert.fail();
            }
        }
        return stateMachine;
    }
}
