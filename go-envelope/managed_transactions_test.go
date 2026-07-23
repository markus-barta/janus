package main

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

const managedTransactionCanary = "SENSITIVE_WEB_TRANSACTION_CANARY_9d3e"

func managedTransactionAccepted(source string) managedAcceptedIntent {
	intent := managedTestIntent(1_784_833_200)
	intent.Source = source
	return managedAcceptedIntent{
		Intent:       intent,
		OperationRef: "op_0123456789abcdef",
	}
}

func managedResponse(request managedTransactionRequest, phase, reason string, expects bool) managedTransactionResponse {
	secretRef := "sec_" + "0123456789abcdef"
	mode := request.Source
	return managedTransactionResponse{
		Schema:        managedTransactionResponseSchema,
		SchemaVersion: managedTransactionSchemaVersion,
		OperationRef:  &request.OperationRef,
		SecretRef:     &secretRef,
		Mode:          &mode,
		Phase:         phase,
		ReasonCode:    reason,
		ExpectsValue:  expects,
		ValueReturned: false,
	}
}

func writeManagedTestResponse(t *testing.T, conn net.Conn, response managedTransactionResponse) {
	t.Helper()
	raw, err := json.Marshal(response)
	if err != nil {
		t.Error(err)
		return
	}
	if err := writeManagedTransactionFrame(conn, raw); err != nil {
		t.Error(err)
	}
}

func TestManagedTransactionImportWaitsForValueFreePreflight(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	client := newManagedTransactionClient("/run/janus/managed-transaction.sock")
	client.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "unix" || address != client.socketPath {
			t.Fatalf("unexpected dial target %s %s", network, address)
		}
		return clientConn, nil
	}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer serverConn.Close()
		rawRequest, err := readManagedTransactionFrame(serverConn)
		if err != nil {
			t.Error(err)
			return
		}
		if strings.Contains(string(rawRequest), managedTransactionCanary) {
			t.Error("value crossed the value-free preflight frame")
			return
		}
		var request managedTransactionRequest
		if err := decodeStrictJSON(rawRequest, &request); err != nil {
			t.Error(err)
			return
		}
		writeManagedTestResponse(t, serverConn, managedResponse(request, "preflighted", "entry_preflight_ok", true))
		value, err := readManagedTransactionFrame(serverConn)
		if err != nil {
			t.Error(err)
			return
		}
		if string(value) != managedTransactionCanary {
			t.Error("import value did not use the single raw frame")
			return
		}
		writeManagedTestResponse(t, serverConn, managedResponse(request, "completed", "entry_activation_ok", false))
	}()

	result, err := client.Execute(
		context.Background(),
		managedTransactionAccepted("import"),
		[]byte(managedTransactionCanary),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Phase != "completed" || result.ValueReturned {
		t.Fatalf("unexpected safe result: %#v", result)
	}
	<-serverDone
}

func TestManagedTransactionGeneratedSendsNoValueFrame(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	client := newManagedTransactionClient("/run/janus/managed-transaction.sock")
	client.dial = func(context.Context, string, string) (net.Conn, error) {
		return clientConn, nil
	}
	go func() {
		defer serverConn.Close()
		rawRequest, err := readManagedTransactionFrame(serverConn)
		if err != nil {
			t.Error(err)
			return
		}
		var request managedTransactionRequest
		if err := decodeStrictJSON(rawRequest, &request); err != nil {
			t.Error(err)
			return
		}
		writeManagedTestResponse(t, serverConn, managedResponse(request, "preflighted", "entry_preflight_ok", false))
		writeManagedTestResponse(t, serverConn, managedResponse(request, "completed", "entry_activation_ok", false))
	}()
	result, err := client.Execute(context.Background(), managedTransactionAccepted("generated"), nil)
	if err != nil || result.Phase != "completed" {
		t.Fatalf("generated transaction failed safely: result=%#v err=%v", result, err)
	}
}

func TestManagedTransactionRejectsValueBeforeGeneratedDial(t *testing.T) {
	client := newManagedTransactionClient("/run/janus/managed-transaction.sock")
	called := false
	client.dial = func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, nil
	}
	_, err := client.Execute(
		context.Background(),
		managedTransactionAccepted("generated"),
		[]byte(managedTransactionCanary),
	)
	if err == nil || err.Error() != "web_transaction_value_denied" || called {
		t.Fatalf("generated value should fail before dial: called=%t err=%v", called, err)
	}
}

func TestManagedTransactionDenialCannotEchoValue(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	client := newManagedTransactionClient("/run/janus/managed-transaction.sock")
	client.dial = func(context.Context, string, string) (net.Conn, error) {
		return clientConn, nil
	}
	go func() {
		defer serverConn.Close()
		rawRequest, err := readManagedTransactionFrame(serverConn)
		if err != nil {
			t.Error(err)
			return
		}
		var request managedTransactionRequest
		if err := decodeStrictJSON(rawRequest, &request); err != nil {
			t.Error(err)
			return
		}
		response := managedResponse(request, "denied", "web_transaction_declaration_denied", false)
		response.SecretRef = nil
		response.Mode = nil
		writeManagedTestResponse(t, serverConn, response)
	}()
	_, err := client.Execute(
		context.Background(),
		managedTransactionAccepted("import"),
		[]byte(managedTransactionCanary),
	)
	if err == nil || err.Error() != "web_transaction_declaration_denied" ||
		strings.Contains(err.Error(), managedTransactionCanary) {
		t.Fatalf("denial should be stable and value-free: %v", err)
	}
}
