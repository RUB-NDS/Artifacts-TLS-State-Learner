/*
 * TLS-StateVulnFinder - A state machine analysis tool based on TLS-Attacker
 *
 * Copyright 2020-2025 Ruhr University Bochum and Paderborn University
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.statevulnfinder.core.algorithm.words;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.statevulnfinder.core.algorithm.responses.UndecryptedAlertsCompoundMessage;
import de.rub.nds.statevulnfinder.core.constants.TlsWordType;
import de.rub.nds.statevulnfinder.core.sul.ReceiveHint;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.http.HttpRequestMessage;
import de.rub.nds.tlsattacker.core.http.HttpResponseMessage;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.RecordCryptoComputations;
import de.rub.nds.tlsattacker.core.record.cipher.RecordBlockCipher;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsscanner.core.vector.response.ResponseExtractor;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.Arrays;

/**
 * @author robert
 */
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class TlsWord {

    private static final Logger LOG = LogManager.getLogger();

    // use a generic receive (with timeout) with probability 1/divisor
    // instead of skipping receiving entirely
    private static int CONFIRM_EMPTY_PROBABILITY_DIVISOR = 4;

    private static Random random = new Random(0L);

    private TlsWordType type;

    private static final ResponseFingerprint ERROR_FINGERPRINT =
            new ResponseFingerprint(new LinkedList<>(), new LinkedList<>(), SocketState.CLOSED);

    public TlsWord() {}

    public TlsWord(TlsWordType type) {
        this.type = type;
    }

    public abstract ResponseFingerprint execute(State state, ReceiveHint receiveHint);

    public TlsWordType getType() {
        return type;
    }

    protected void sendMessage(DataContainer message, Record record, State state) {
        SendAction sendAction;
        if (message instanceof ProtocolMessage) {
            ProtocolMessage protocolMsg = (ProtocolMessage) message;
            stripFields(protocolMsg);
            sendAction = new SendAction(protocolMsg);
        } else if (message instanceof HttpMessage) {
            sendAction = new SendAction((HttpMessage) message);
        } else {
            throw new IllegalArgumentException("Unknown message type for " + message.getClass());
        }
        if (state.getTlsContext().getSelectedCipherSuite() != null
                && state.getTlsContext().getSelectedCipherSuite().isCBC()
                && state.getTlsContext().getRecordLayer().getEncryptorCipher()
                        instanceof RecordBlockCipher) {
            if (record.getComputations() == null) {
                record.setComputations(new RecordCryptoComputations());
            }
            byte[] realIv =
                    ((RecordBlockCipher)
                                    state.getTlsContext().getRecordLayer().getEncryptorCipher())
                            .getEncryptionIV();
            // force first bytes to be 0 to avoid ambuiguity when we activated encryption but peer
            // didn't and initial bytes are interpreted as handshake message header
            // we use 27 as it is the first currently undefined handshake message type
            Arrays.fill(realIv, 0, 4, (byte) 0x00);
            realIv[0] = (byte) 27;
            record.getComputations().setCbcInitialisationVector(Modifiable.explicit(realIv));
        }
        sendAction.setRecords(record);
        sendAction.setConnectionAlias(state.getTlsContext().getConnection().getAlias());
        sendAction.execute(state);
    }

    private void stripFields(ProtocolMessage message) {
        List<ModifiableVariableHolder> holders = new LinkedList<>();
        holders.addAll(message.getAllModifiableVariableHolders());
        for (ModifiableVariableHolder holder : holders) {
            List<Field> fields = holder.getAllModifiableVariableFields();
            for (Field f : fields) {
                f.setAccessible(true);

                ModifiableVariable mv = null;
                try {
                    mv = (ModifiableVariable) f.get(holder);
                } catch (IllegalArgumentException | IllegalAccessException ex) {
                    ex.printStackTrace();
                }
                if (mv != null) {
                    if (mv.getModification() != null || mv.isCreateRandomModification()) {
                        mv.setOriginalValue(null);
                    } else {
                        try {
                            f.set(holder, null);
                        } catch (IllegalArgumentException | IllegalAccessException ex) {
                            ex.printStackTrace();
                        }
                    }
                }
            }
        }
    }

    protected ResponseFingerprint receiveMessages(State state, ReceiveHint receiveHint) {
        try {
            if (state.getTlsContext().getTransportHandler().isClosed()) {
                return ERROR_FINGERPRINT;
            }
        } catch (IOException ex) {
            LOG.error("Failed to determine socket state", ex);
            return ERROR_FINGERPRINT;
        }
        try {
            if (receiveHint.hasExpectation()) {
                return smartReplaceFingerprint(
                        state, receiveHint, receiveWithHint(receiveHint, state));
            } else {
                return smartReplaceFingerprint(state, receiveHint, receiveGeneric(state));
            }
        } catch (Exception ex) {
            LOG.error("Failed to obtain response fingerprint ", ex);
            return ERROR_FINGERPRINT;
        }
    }

    /**
     * Perform
     *
     * @param state
     * @param receivehint
     * @return
     */
    protected ResponseFingerprint smartReplaceFingerprint(
            State state, ReceiveHint receivehint, ResponseFingerprint responseFingerprint) {
        replaceUndecryptedAlerts(responseFingerprint);
        return responseFingerprint;
    }

    public static void replaceUndecryptedAlerts(ResponseFingerprint responseFingerprint) {
        boolean filterApplies = false;
        if (responseFingerprint != null
                && responseFingerprint.getMessageList() != null
                && !responseFingerprint.getMessageList().isEmpty()) {
            List<AlertMessage> alertsFound =
                    responseFingerprint.getMessageList().stream()
                            .filter(
                                    message ->
                                            message.getProtocolMessageType()
                                                    == ProtocolMessageType.ALERT)
                            .map(message -> (AlertMessage) message)
                            .collect(Collectors.toList());

            // we typically identify these error cases based on a flood of alerts where most have an
            // undefined alert level as the value is pseudo-random and there are only two defined
            // byte values (warning/fatal)
            boolean anyUnknown =
                    alertsFound.stream()
                            .anyMatch(
                                    alert ->
                                            AlertLevel.getAlertLevel(alert.getLevel().getValue())
                                                    == AlertLevel.UNDEFINED);

            filterApplies = alertsFound.size() > 2 && anyUnknown;
            if (filterApplies) {
                List<ProtocolMessage> originalMessages = responseFingerprint.getMessageList();
                List<ProtocolMessage> newMessages = new LinkedList<>();

                List<AlertMessage> currentSubList = new LinkedList<>();

                for (ProtocolMessage message : originalMessages) {
                    if (message.getProtocolMessageType() == ProtocolMessageType.ALERT) {
                        currentSubList.add((AlertMessage) message);
                    } else {
                        if (!currentSubList.isEmpty()) {
                            newMessages.add(new UndecryptedAlertsCompoundMessage(currentSubList));
                            currentSubList.clear();
                        }
                        newMessages.add(message);
                    }
                }

                if (!currentSubList.isEmpty()) {
                    if (currentSubList.size() < 3) {
                        // retain original alerts
                        newMessages.addAll(currentSubList);
                    } else {
                        // merge multiple alerts
                        newMessages.add(new UndecryptedAlertsCompoundMessage(currentSubList));
                    }
                }

                responseFingerprint.getMessageList().clear();
                responseFingerprint.getMessageList().addAll(newMessages);
            }
        }
    }

    private ResponseFingerprint receiveGeneric(State state) {
        GenericReceiveAction action =
                new GenericReceiveAction(state.getTlsContext().getConnection().getAlias());
        action.execute(state);
        return ResponseExtractor.getFingerprint(state, action);
    }

    private ResponseFingerprint receiveWithHint(ReceiveHint receiveHint, State state)
            throws WorkflowExecutionException {
        if (receiveHint.getExpectedMessages().isEmpty()) {
            if (confirmEmptyResponse()) {
                return receiveGeneric(state);
            } else {
                return new ResponseFingerprint(
                        new LinkedList<>(), new LinkedList<>(), receiveHint.getSocketState());
            }
        } else {
            ReceiveAction action =
                    new ReceiveAction(
                            state.getTlsContext().getConnection().getAlias(),
                            receiveHint.getExpectedMessages());
            action.execute(state);
            ResponseFingerprint responseFingerprint =
                    ResponseExtractor.getFingerprint(state, action);
            if (socketStateNotClosedAsExpected(responseFingerprint, receiveHint)) {
                responseFingerprint =
                        reEvaluateSocketState(state, responseFingerprint, action, receiveHint);
            }
            return responseFingerprint;
        }
    }

    private ResponseFingerprint reEvaluateSocketState(
            State state,
            ResponseFingerprint responseFingerprint,
            ReceiveAction action,
            ReceiveHint receiveHint) {
        long systime = System.currentTimeMillis();
        long timeout = state.getTlsContext().getTransportHandler().getTimeout();
        do {
            try {
                Thread.sleep(100);
                responseFingerprint = ResponseExtractor.getFingerprint(state, action);
            } catch (Exception ignored) {
            }
        } while (System.currentTimeMillis() - systime < timeout
                && socketStateNotClosedAsExpected(responseFingerprint, receiveHint));
        return responseFingerprint;
    }

    private static boolean socketStateNotClosedAsExpected(
            ResponseFingerprint responseFingerprint, ReceiveHint receiveHint) {
        return responseFingerprint.getSocketState() != receiveHint.getSocketState()
                && (receiveHint.getSocketState() == SocketState.CLOSED
                        || receiveHint.getSocketState() == SocketState.SOCKET_EXCEPTION);
    }

    public String toShortString() {
        return this.getClass().toString();
    }

    public static boolean isAppData(DataContainer message) {
        return message instanceof HttpResponseMessage
                || message instanceof ApplicationMessage
                || message instanceof HttpRequestMessage;
    }

    private boolean confirmEmptyResponse() {
        return random.nextInt(CONFIRM_EMPTY_PROBABILITY_DIVISOR) == 0;
    }
}
