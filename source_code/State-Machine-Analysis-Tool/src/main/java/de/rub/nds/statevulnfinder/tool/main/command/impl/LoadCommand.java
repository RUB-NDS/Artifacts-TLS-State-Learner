/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.main.command.impl;

import de.rub.nds.statevulnfinder.core.StateMachine;
import de.rub.nds.statevulnfinder.core.algorithm.words.TlsWord;
import de.rub.nds.statevulnfinder.core.extraction.alphabet.NamedListAlphabet;
import de.rub.nds.statevulnfinder.core.util.TestUtils;
import de.rub.nds.statevulnfinder.tool.main.command.AbstractCommand;
import de.rub.nds.statevulnfinder.tool.main.command.CommandContext;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;

/** Command to load a state machine from an XML file. */
public class LoadCommand extends AbstractCommand {

    @Override
    public String getName() {
        return "load";
    }

    @Override
    public String getDescription() {
        return "Load state machine XML from the specified path";
    }

    @Override
    public String getUsage() {
        return "load <path>";
    }

    @Override
    public boolean requiresStateMachine() {
        return false;
    }

    @Override
    protected boolean validateArguments(String[] args) {
        return args.length == 1;
    }

    @Override
    protected void executeCommand(String[] args, CommandContext context) {
        String path = args[0];
        LOG.info("Loading state machine from {}", path);

        StateMachine stateMachine = TestUtils.loadStateMachine(path);
        context.setStateMachine(stateMachine);
        context.setXmlFilePath(path);

        if (!context.isStateMachineLoaded()) {
            LOG.error("StateMachine was not loaded");
        } else {
            List<TlsWord> sortedAlphabet = new LinkedList<>(stateMachine.getAlphabet());
            sortedAlphabet.sort(Comparator.comparing(Object::toString));
            stateMachine.setAlphabet(new NamedListAlphabet<>(sortedAlphabet));
            LOG.info(
                    "Loaded state machine - alphabet size: {}, states: {}",
                    stateMachine.getAlphabet().size(),
                    stateMachine.getMealyMachine().getStates().size());
        }
    }
}
