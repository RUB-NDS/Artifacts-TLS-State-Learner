#!/bin/bash

echo "OpenSSL version:"
/usr/local/openssl/bin/openssl version

# Start tmux session
tmux new-session -d -s tls-state-learner

# Split window horizontally
tmux split-window -h

# In the left pane (pane 0), start OpenSSL server
tmux send-keys -t tls-state-learner:0.0 "/usr/local/openssl/bin/openssl s_server -accept 4433 -cert /app/server.crt -key /app/server.key" Enter

# Wait for OpenSSL to start
sleep 3

# Create a wrapper script that runs the JAR and exits tmux when done
cat > /tmp/jar-wrapper.sh << EOF
#!/bin/bash
cd /app/apps
java -jar TLS-Server-StateVulnFinder.jar -connect localhost:4433 -minTimeout 50 -searchPattern ITERATIVE -equivalenceAlgorithm RANDOM_WORDS_STATE -output /output/ $@
JAR_EXIT_CODE=\$?

# Copy the log file to /output if it exists
if [ -f logs/app.log ]; then
  cp logs/app.log /output/
  echo "Log file copied to /output/app.log"
fi

if [ \$JAR_EXIT_CODE -eq 0 ]; then
  tmux kill-session -t tls-state-learner
else
  echo ""
  echo "Execution of the state learner was unsuccessful. Please report any issues indicated above."
  echo ""
fi
exit \$JAR_EXIT_CODE
EOF

chmod +x /tmp/jar-wrapper.sh

# Run the wrapper script in the right pane
tmux send-keys -t tls-state-learner:0.1 "/tmp/jar-wrapper.sh" Enter

# Attach to tmux session
tmux attach-session -t tls-state-learner
