/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.main.command;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Registry for all available commands. */
public class CommandRegistry {

    private static final Logger LOG = LogManager.getLogger(CommandRegistry.class);

    private final Map<String, Command> commands = new HashMap<>();
    private final Map<String, String> aliases = new HashMap<>();

    /**
     * Register a command.
     *
     * @param command The command to register
     */
    public void register(Command command) {
        String name = command.getName().toLowerCase();
        if (commands.containsKey(name)) {
            LOG.warn("Command '{}' is already registered, overwriting.", name);
        }
        commands.put(name, command);

        // Register aliases
        for (String alias : command.getAliases()) {
            String lowerAlias = alias.toLowerCase();
            if (aliases.containsKey(lowerAlias)) {
                LOG.warn("Alias '{}' is already registered, overwriting.", alias);
            }
            aliases.put(lowerAlias, name);
        }
    }

    /**
     * Get a command by name or alias.
     *
     * @param nameOrAlias Command name or alias
     * @return The command, or null if not found
     */
    public Command getCommand(String nameOrAlias) {
        String lower = nameOrAlias.toLowerCase();

        // Try direct lookup
        Command command = commands.get(lower);
        if (command != null) {
            return command;
        }

        // Try alias lookup
        String actualName = aliases.get(lower);
        if (actualName != null) {
            return commands.get(actualName);
        }

        return null;
    }

    /**
     * Get all registered commands sorted by name.
     *
     * @return Map of command name to command
     */
    public Map<String, Command> getAllCommands() {
        return new TreeMap<>(commands);
    }

    /**
     * Check if a command exists.
     *
     * @param nameOrAlias Command name or alias
     * @return true if the command exists
     */
    public boolean hasCommand(String nameOrAlias) {
        return getCommand(nameOrAlias) != null;
    }
}
