/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.tool.main;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import de.rub.nds.statevulnfinder.server.config.ServerSulDelegate;
import de.rub.nds.statevulnfinder.server.config.ServerVulnerabilityFinderConfig;
import de.rub.nds.statevulnfinder.tool.main.command.*;
import de.rub.nds.statevulnfinder.tool.main.command.impl.*;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Scanner;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Main application class for the State Machine Analysis Tool. */
public class StateMachineAnalysisTool {

    private static final Logger LOG = LogManager.getLogger(StateMachineAnalysisTool.class);

    @Parameter(
            names = {"-f", "--file"},
            description = "XML file to load on startup")
    private String xmlFile;

    @Parameter(
            names = {"-c", "--command"},
            description = "Command to execute and then exit")
    private String command;

    @Parameter(
            names = {"-a", "--analyze-first"},
            description = "Run analyze command before executing the command given in -c")
    private boolean analyzeFirst;

    @Parameter(
            names = {"-h", "--help"},
            help = true,
            description = "Show help")
    private boolean help;

    private final CommandRegistry commandRegistry = new CommandRegistry();
    private final CommandContext context = new CommandContext();

    public static void main(String[] args) {
        StateMachineAnalysisTool tool = new StateMachineAnalysisTool();
        tool.run(args);
    }

    public void run(String[] args) {
        // Parse command line arguments
        JCommander jCommander = JCommander.newBuilder().addObject(this).build();
        jCommander.setProgramName("StateMachineAnalysisTool");

        try {
            jCommander.parse(args);
        } catch (ParameterException e) {
            LOG.error("Error parsing arguments: {}", e.getMessage());
            jCommander.usage();
            System.exit(1);
        }

        if (help) {
            jCommander.usage();
            System.exit(0);
        }

        // Initialize commands
        initializeCommands();

        // Load XML file if specified
        if (xmlFile != null) {
            loadXmlFile(xmlFile);
        }

        // Execute command if specified
        if (command != null) {
            // Run analyze command first if -a flag is specified
            if (analyzeFirst) {
                context.setSilentMode(true);
                executeCommand("analyze");
                context.setSilentMode(false);
            }
            executeCommand(command);
            System.exit(0);
        }

        // Enter interactive mode
        commandLoop();
    }

    private void initializeCommands() {
        // Register all commands
        commandRegistry.register(new LoadCommand());
        commandRegistry.register(new HelpCommand(commandRegistry));
        commandRegistry.register(new ExitCommand());
        commandRegistry.register(new AnalyzeCommand());
        commandRegistry.register(new AlphabetCommand());
        commandRegistry.register(new DiffStatesCommand());
        commandRegistry.register(new SuccessorsCommand());
        commandRegistry.register(new PredecessorsCommand());
        commandRegistry.register(new PathCommand());
        commandRegistry.register(new InfoCommand());
        commandRegistry.register(new ListStatesCommand());
        commandRegistry.register(new QueryCommand());
        commandRegistry.register(new SimulateQueryCommand());
        commandRegistry.register(new ScanCommand());
        commandRegistry.register(new PrintScanCommand());
        commandRegistry.register(new MessageSequencesCommand());
        commandRegistry.register(new SetTimeoutCommand());
        commandRegistry.register(new WriteDotCommand());
        commandRegistry.register(new AnonymizeCommand());
        commandRegistry.register(new CheckCommonIssuesCommand());
        commandRegistry.register(new CheckInterestingPropertiesCommand());
        // Add more commands as they are implemented
    }

    private void loadXmlFile(String xmlPath) {
        Path path = Paths.get(xmlPath);
        String hostname = path.getFileName().toString().replace(".xml", "");
        LOG.info("Assuming target '{}:443'.", hostname);

        ServerVulnerabilityFinderConfig config =
                new ServerVulnerabilityFinderConfig(new GeneralDelegate());
        config.setImplementationName(hostname);

        try {
            config.getDelegate(ServerSulDelegate.class).setHost(hostname + ":443");
            LOG.info("Assuming target '{}:443'.", hostname);
        } catch (Exception e) {
            LOG.warn(
                    "Was unable to parse host from provided XML. Specify the hostname manually when using 'scan' command.");
        }

        context.setConfig(config);

        // Execute load command
        Command loadCommand = commandRegistry.getCommand("load");
        loadCommand.execute(new String[] {xmlPath}, context);

        if (context.isStateMachineLoaded()) {
            context.getStateMachine().setVulnerabilityFinderConfig(config);
        }
    }

    private void commandLoop() {
        Scanner scanner = new Scanner(System.in);

        while (true) {
            LOG.info("\n");
            String input = scanner.nextLine();
            executeCommand(input);
        }
    }

    private void executeCommand(String input) {
        if (input.trim().isEmpty()) {
            return;
        }

        String[] parts = input.trim().split("\\s+");
        String commandName = parts[0];
        String[] args = Arrays.copyOfRange(parts, 1, parts.length);

        Command command = commandRegistry.getCommand(commandName);
        if (command == null) {
            LOG.warn("Unknown command '{}'. Try 'help'", commandName);
            return;
        }

        try {
            command.execute(args, context);
        } catch (Exception e) {
            LOG.error("Error executing command '{}': {}", commandName, e.getMessage(), e);
        }

        LOG.info("\n");
    }
}
