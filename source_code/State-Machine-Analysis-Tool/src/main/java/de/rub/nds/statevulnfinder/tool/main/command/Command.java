/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.main.command;

/** Interface for all commands in the State Machine Analysis Tool. */
public interface Command {

    /**
     * Execute the command with the given arguments.
     *
     * @param args Command arguments (excluding the command name itself)
     * @param context The command context containing shared state
     */
    void execute(String[] args, CommandContext context);

    /**
     * Get the primary name of this command.
     *
     * @return The command name
     */
    String getName();

    /**
     * Get aliases for this command.
     *
     * @return Array of command aliases, or empty array if none
     */
    default String[] getAliases() {
        return new String[0];
    }

    /**
     * Get a brief description of what this command does.
     *
     * @return Command description
     */
    String getDescription();

    /**
     * Get detailed usage information for this command.
     *
     * @return Usage string
     */
    String getUsage();

    /**
     * Check if this command requires a loaded state machine.
     *
     * @return true if state machine is required
     */
    default boolean requiresStateMachine() {
        return true;
    }

    /**
     * Check if this command requires analysis to be run first.
     *
     * @return true if analysis is required
     */
    default boolean requiresAnalysis() {
        return false;
    }
}
