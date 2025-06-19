/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.main.command;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Abstract base class for commands providing common functionality. */
public abstract class AbstractCommand implements Command {

    protected static final Logger LOG = LogManager.getLogger(AbstractCommand.class);

    @Override
    public void execute(String[] args, CommandContext context) {
        // Check preconditions
        if (requiresStateMachine() && !context.isStateMachineLoaded()) {
            LOG.warn("No StateMachine loaded. Use 'load <path>' first.");
            return;
        }

        if (requiresAnalysis() && !context.isGraphDetailsAnalyzed()) {
            LOG.warn("State machine not analyzed. Use 'analyze' first.");
            return;
        }

        // Validate arguments
        if (!validateArguments(args)) {
            LOG.warn("Invalid arguments. Usage: {}", getUsage());
            return;
        }

        // Execute the actual command logic
        executeCommand(args, context);
    }

    /**
     * Validate command arguments.
     *
     * @param args Command arguments
     * @return true if arguments are valid
     */
    protected abstract boolean validateArguments(String[] args);

    /**
     * Execute the command logic. This method is called after preconditions and arguments have been
     * validated.
     *
     * @param args Command arguments
     * @param context Command context
     */
    protected abstract void executeCommand(String[] args, CommandContext context);
}
