/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.main.command.impl;

import de.rub.nds.statevulnfinder.tool.main.command.AbstractCommand;
import de.rub.nds.statevulnfinder.tool.main.command.Command;
import de.rub.nds.statevulnfinder.tool.main.command.CommandContext;
import de.rub.nds.statevulnfinder.tool.main.command.CommandRegistry;
import java.util.Map;

/** Command to display help information. */
public class HelpCommand extends AbstractCommand {

    private final CommandRegistry registry;

    public HelpCommand(CommandRegistry registry) {
        this.registry = registry;
    }

    @Override
    public String getName() {
        return "help";
    }

    @Override
    public String[] getAliases() {
        return new String[] {"h"};
    }

    @Override
    public String getDescription() {
        return "Display this help message";
    }

    @Override
    public String getUsage() {
        return "help [command]";
    }

    @Override
    public boolean requiresStateMachine() {
        return false;
    }

    @Override
    protected boolean validateArguments(String[] args) {
        return args.length == 0 || args.length == 1;
    }

    @Override
    protected void executeCommand(String[] args, CommandContext context) {
        if (args.length == 1) {
            // Show help for specific command
            String commandName = args[0];
            Command command = registry.getCommand(commandName);
            if (command == null) {
                LOG.warn("Unknown command: {}", commandName);
                return;
            }

            LOG.info("Command: {}", command.getName());
            if (command.getAliases().length > 0) {
                LOG.info("Aliases: {}", String.join(", ", command.getAliases()));
            }
            LOG.info("Description: {}", command.getDescription());
            LOG.info("Usage: {}", command.getUsage());
            if (command.requiresStateMachine()) {
                LOG.info("Note: This command requires a loaded state machine");
            }
            if (command.requiresAnalysis()) {
                LOG.info("Note: This command requires analysis to be run first");
            }
        } else {
            // Show general help
            LOG.info("Available Commands:");
            Map<String, Command> commands = registry.getAllCommands();

            // Calculate max width for alignment
            int maxWidth =
                    commands.values().stream()
                            .mapToInt(
                                    cmd -> {
                                        int width = cmd.getName().length();
                                        if (cmd.getAliases().length > 0) {
                                            width +=
                                                    2
                                                            + String.join(", ", cmd.getAliases())
                                                                    .length()
                                                            + 2; // " | " + aliases + " "
                                        }
                                        return width;
                                    })
                            .max()
                            .orElse(20);

            for (Command command : commands.values()) {
                String nameAndAliases = command.getName();
                if (command.getAliases().length > 0) {
                    nameAndAliases += " | " + String.join(", ", command.getAliases());
                }

                // Pad the nameAndAliases to ensure alignment
                String paddedName = String.format("%-" + (maxWidth + 5) + "s", nameAndAliases);

                LOG.info("  {} - {}", paddedName, command.getDescription());
            }
            LOG.info("\nType 'help <command>' for detailed information about a specific command.");
        }
    }
}
