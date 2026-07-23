package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

const (
	managedTransactionRequestSchema  = "inspr.janus.managed-web-transaction-request.v1"
	managedTransactionResponseSchema = "inspr.janus.managed-web-transaction-response.v1"
	managedTransactionSchemaVersion  = 1
	managedTransactionMaxFrameBytes  = 64 * 1024
	managedTransactionDialTimeout    = 3 * time.Second
	managedTransactionTotalTimeout   = 35 * time.Second
)

type managedTransactionRequest struct {
	Schema                 string `json:"schema"`
	SchemaVersion          int    `json:"schema_version"`
	OperationRef           string `json:"operation_ref"`
	OperationKind          string `json:"operation_kind"`
	Source                 string `json:"source"`
	HostRef                string `json:"host_ref"`
	ServiceRef             string `json:"service_ref"`
	SlotRef                string `json:"slot_ref"`
	DeclarationFingerprint string `json:"declaration_fingerprint"`
}

type managedTransactionResponse struct {
	Schema        string  `json:"schema"`
	SchemaVersion int     `json:"schema_version"`
	OperationRef  *string `json:"operation_ref"`
	SecretRef     *string `json:"secret_ref"`
	Mode          *string `json:"mode"`
	Phase         string  `json:"phase"`
	ReasonCode    string  `json:"reason_code"`
	ExpectsValue  bool    `json:"expects_value"`
	ValueReturned bool    `json:"value_returned"`
}

type managedTransactionResult struct {
	OperationRef  string
	SecretRef     string
	Mode          string
	Phase         string
	ReasonCode    string
	ValueReturned bool
}

type managedTransactionClient struct {
	socketPath string
	dial       func(context.Context, string, string) (net.Conn, error)
	now        func() time.Time
}

type managedTransactionExecutor interface {
	Execute(context.Context, managedAcceptedIntent, []byte) (managedTransactionResult, error)
}

func newManagedTransactionClient(socketPath string) *managedTransactionClient {
	dialer := &net.Dialer{Timeout: managedTransactionDialTimeout}
	return &managedTransactionClient{
		socketPath: socketPath,
		dial:       dialer.DialContext,
		now:        time.Now,
	}
}

func (client *managedTransactionClient) Execute(ctx context.Context, accepted managedAcceptedIntent, importedValue []byte) (managedTransactionResult, error) {
	request := managedTransactionRequest{
		Schema:                 managedTransactionRequestSchema,
		SchemaVersion:          managedTransactionSchemaVersion,
		OperationRef:           accepted.OperationRef,
		OperationKind:          accepted.Intent.OperationKind,
		Source:                 accepted.Source,
		HostRef:                accepted.Intent.HostRef,
		ServiceRef:             accepted.Intent.ServiceRef,
		SlotRef:                accepted.Intent.SlotRef,
		DeclarationFingerprint: accepted.Intent.DeclarationFingerprint,
	}
	if err := validateManagedTransactionRequest(request, importedValue); err != nil {
		return managedTransactionResult{}, err
	}
	conn, err := client.dial(ctx, "unix", client.socketPath)
	if err != nil {
		return managedTransactionResult{}, managedTransactionError("web_transaction_unavailable")
	}
	defer conn.Close()
	deadline := client.now().Add(managedTransactionTotalTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return managedTransactionResult{}, managedTransactionError("web_transaction_unavailable")
	}

	header, err := json.Marshal(request)
	if err != nil || writeManagedTransactionFrame(conn, header) != nil {
		return managedTransactionResult{}, managedTransactionError("web_transaction_unavailable")
	}
	first, err := readManagedTransactionResponse(conn, request)
	if err != nil {
		return managedTransactionResult{}, err
	}
	if first.Phase == "completed" {
		return transactionResult(first), nil
	}
	if first.Phase == "rolled_back" {
		return managedTransactionResult{}, managedTransactionError("web_transaction_rolled_back")
	}
	if first.Phase != "preflighted" || first.ExpectsValue != (request.Source == "import") {
		return managedTransactionResult{}, managedTransactionError("web_transaction_protocol_invalid")
	}
	if request.Source == "import" {
		if err := writeManagedTransactionFrame(conn, importedValue); err != nil {
			return managedTransactionResult{}, managedTransactionError("web_transaction_unavailable")
		}
	}
	final, err := readManagedTransactionResponse(conn, request)
	if err != nil {
		return managedTransactionResult{}, err
	}
	if final.ExpectsValue || final.Phase != "completed" {
		return managedTransactionResult{}, managedTransactionError("web_transaction_incomplete")
	}
	return transactionResult(final), nil
}

func validateManagedTransactionRequest(request managedTransactionRequest, importedValue []byte) error {
	if request.Schema != managedTransactionRequestSchema ||
		request.SchemaVersion != managedTransactionSchemaVersion ||
		!validManagedRef("op_", request.OperationRef) ||
		!validManagedRef("host_", request.HostRef) ||
		!validManagedRef("svc_", request.ServiceRef) ||
		!validManagedRef("slot_", request.SlotRef) ||
		!validManagedRef("decl_", request.DeclarationFingerprint) ||
		(request.OperationKind != "create" && request.OperationKind != "replace") ||
		(request.Source != "generated" && request.Source != "import") {
		return managedTransactionError("web_transaction_request_invalid")
	}
	if request.Source == "generated" && len(importedValue) != 0 {
		return managedTransactionError("web_transaction_value_denied")
	}
	if request.Source == "import" && (len(importedValue) == 0 || len(importedValue) > managedTransactionMaxFrameBytes) {
		return managedTransactionError("web_transaction_value_invalid")
	}
	return nil
}

func readManagedTransactionResponse(conn net.Conn, request managedTransactionRequest) (managedTransactionResponse, error) {
	raw, err := readManagedTransactionFrame(conn)
	if err != nil {
		return managedTransactionResponse{}, managedTransactionError("web_transaction_unavailable")
	}
	var response managedTransactionResponse
	if decodeStrictJSON(raw, &response) != nil ||
		response.Schema != managedTransactionResponseSchema ||
		response.SchemaVersion != managedTransactionSchemaVersion ||
		response.ValueReturned ||
		!validManagedTransactionPhase(response.Phase) ||
		!validManagedTransactionReason(response.ReasonCode) {
		return managedTransactionResponse{}, managedTransactionError("web_transaction_protocol_invalid")
	}
	if response.Phase == "denied" {
		return managedTransactionResponse{}, managedTransactionError(response.ReasonCode)
	}
	if response.OperationRef == nil || *response.OperationRef != request.OperationRef ||
		response.SecretRef == nil || !validManagedRef("sec_", *response.SecretRef) ||
		response.Mode == nil || *response.Mode != request.Source {
		return managedTransactionResponse{}, managedTransactionError("web_transaction_protocol_invalid")
	}
	return response, nil
}

func writeManagedTransactionFrame(writer io.Writer, body []byte) error {
	if len(body) == 0 || len(body) > managedTransactionMaxFrameBytes {
		return errors.New("managed transaction frame length denied")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	if err := writeManagedTransactionBytes(writer, header[:]); err != nil {
		return err
	}
	return writeManagedTransactionBytes(writer, body)
}

func writeManagedTransactionBytes(writer io.Writer, body []byte) error {
	for len(body) > 0 {
		written, err := writer.Write(body)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(body) {
			return io.ErrShortWrite
		}
		body = body[written:]
	}
	return nil
}

func readManagedTransactionFrame(reader io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(header[:]))
	if length <= 0 || length > managedTransactionMaxFrameBytes {
		return nil, errors.New("managed transaction frame length denied")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	return body, nil
}

func transactionResult(response managedTransactionResponse) managedTransactionResult {
	return managedTransactionResult{
		OperationRef:  *response.OperationRef,
		SecretRef:     *response.SecretRef,
		Mode:          *response.Mode,
		Phase:         response.Phase,
		ReasonCode:    response.ReasonCode,
		ValueReturned: false,
	}
}

type managedTransactionError string

func (err managedTransactionError) Error() string { return string(err) }

func validManagedTransactionReason(reason string) bool {
	if len(reason) < 3 || len(reason) > 96 ||
		(!strings.HasPrefix(reason, "entry_") && !strings.HasPrefix(reason, "web_transaction_")) {
		return false
	}
	for _, character := range reason {
		if (character < 'a' || character > 'z') && character != '_' {
			return false
		}
	}
	return true
}

func validManagedTransactionPhase(phase string) bool {
	switch phase {
	case "denied", "preflighted", "completed", "rolled_back":
		return true
	default:
		return false
	}
}
