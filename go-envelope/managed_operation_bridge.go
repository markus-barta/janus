package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	managedOperationBridgeSchema       = "inspr.janus.managed-operation-bridge.v1"
	managedOperationBridgeVersion      = 1
	managedOperationReadySchema        = "inspr.janus.managed-service-operation-ready.v1"
	managedOperationStatusSchema       = "inspr.pharos.managed-service-operation-status.v1"
	managedHostOutboxSchema            = "inspr.janus.managed-host-envelope-outbox.v1"
	managedHostTokenGenerationSchema   = "inspr.pharos.beacon-token-generation.v2"
	managedHostReconcileRequestSchema  = "inspr.janus.managed-host-reconcile-request.v1"
	managedOperationBridgeMaxEntries   = 4096
	managedOperationBridgeMaxBytes     = int64(2 * 1024 * 1024)
	managedHostOutboxMaxBytes          = int64(512 * 1024)
	managedTokenGenerationMaxBytes     = int64(1024 * 1024)
	managedTokenGenerationCurrentBytes = int64(65)
)

type managedOperationBridgeRecord struct {
	OperationRef           string `json:"operation_ref"`
	OperationKind          string `json:"operation_kind"`
	Source                 string `json:"source"`
	HostRef                string `json:"host_ref"`
	ServiceRef             string `json:"service_ref"`
	SlotRef                string `json:"slot_ref"`
	DeclarationFingerprint string `json:"declaration_fingerprint"`
	DeliveryProfileRef     string `json:"delivery_profile_ref"`
	ReloadProfileRef       string `json:"reload_profile_ref"`
	HealthProfileRef       string `json:"health_profile_ref"`
	Generation             uint64 `json:"generation"`
	Phase                  string `json:"phase"`
	CreatedAtUnixSeconds   int64  `json:"created_at_unix_secs"`
	UpdatedAtUnixSeconds   int64  `json:"updated_at_unix_secs"`
	ValueReturned          bool   `json:"value_returned"`
}

type managedOperationBridgeDocument struct {
	Schema        string                                  `json:"schema"`
	SchemaVersion int                                     `json:"schema_version"`
	Operations    map[string]managedOperationBridgeRecord `json:"operations"`
}

type managedOperationBridgeStore struct {
	path     string
	mu       sync.Mutex
	document managedOperationBridgeDocument
}

type managedOperationBridge struct {
	transaction managedTransactionBackend
	pharos      *managedPharosOperationClient
	store       *managedOperationBridgeStore
	outboxDir   string
	tokens      *managedHostTokenVerifier
	now         func() time.Time
}

type managedPharosOperationClient struct {
	origin string
	token  string
	client *http.Client
}

type managedOperationReadyRequest struct {
	Schema                 string `json:"schema"`
	SchemaVersion          int    `json:"schema_version"`
	OperationRef           string `json:"operation_ref"`
	OperationKind          string `json:"operation_kind"`
	HostRef                string `json:"host_ref"`
	ServiceRef             string `json:"service_ref"`
	SlotRef                string `json:"slot_ref"`
	DeclarationFingerprint string `json:"declaration_fingerprint"`
	Generation             uint64 `json:"generation"`
	ValueReturned          bool   `json:"value_returned"`
}

type managedPharosOperationStatus struct {
	Schema        string                        `json:"schema"`
	SchemaVersion int                           `json:"schema_version"`
	Operation     managedPharosOperationSummary `json:"operation"`
	ValueReturned bool                          `json:"value_returned"`
}

type managedPharosOperationSummary struct {
	OperationRef           string                      `json:"operation_ref"`
	OperationKind          string                      `json:"operation_kind"`
	HostRef                string                      `json:"host_ref"`
	ServiceRef             string                      `json:"service_ref"`
	SlotRef                string                      `json:"slot_ref"`
	DeclarationFingerprint string                      `json:"declaration_fingerprint"`
	Generation             uint64                      `json:"generation"`
	Phase                  string                      `json:"phase"`
	ReasonCode             *string                     `json:"reason_code"`
	CreatedAtUnixSeconds   int64                       `json:"created_at_unix_secs"`
	UpdatedAtUnixSeconds   int64                       `json:"updated_at_unix_secs"`
	Health                 *managedPharosHealthSummary `json:"health"`
	ValueReturned          bool                        `json:"value_returned"`
}

type managedPharosHealthSummary struct {
	Generation                     uint64 `json:"generation"`
	Outcome                        string `json:"outcome"`
	HeartbeatObservedAtUnixSeconds int64  `json:"heartbeat_observed_at_unix_secs"`
	ProcessObservedAtUnixSeconds   int64  `json:"process_observed_at_unix_secs"`
	ProbeObservedAtUnixSeconds     int64  `json:"probe_observed_at_unix_secs"`
	AcceptedAtUnixSeconds          int64  `json:"accepted_at_unix_secs"`
}

type managedHostOutboxRecord struct {
	Schema                 string `json:"schema"`
	SchemaVersion          int    `json:"schema_version"`
	OperationRef           string `json:"operation_ref"`
	OperationKind          string `json:"operation_kind"`
	HostRef                string `json:"host_ref"`
	ServiceRef             string `json:"service_ref"`
	SlotRef                string `json:"slot_ref"`
	SecretRef              string `json:"secret_ref"`
	ScopeRef               string `json:"scope_ref"`
	DeclarationFingerprint string `json:"declaration_fingerprint"`
	EnvelopeRef            string `json:"envelope_ref"`
	Generation             uint64 `json:"generation"`
	RevocationEpoch        uint64 `json:"revocation_epoch"`
	PreparedAtUnixSeconds  int64  `json:"prepared_at_unix_secs"`
	ExpiresAtUnixSeconds   int64  `json:"expires_at_unix_secs"`
	PacketBase64           string `json:"packet_base64"`
	ValueReturned          bool   `json:"value_returned"`
	IntegrityHash          string `json:"integrity_hash"`
}

type managedHostReconcileRequest struct {
	Schema        string `json:"schema"`
	SchemaVersion int    `json:"schema_version"`
	OperationRef  string `json:"operation_ref"`
	HostRef       string `json:"host_ref"`
	Generation    uint64 `json:"generation"`
}

type managedHostTokenVerifier struct {
	root string
}

type managedHostTokenGeneration struct {
	Schema     string                            `json:"schema"`
	Generation string                            `json:"generation"`
	Hosts      []managedHostTokenGenerationEntry `json:"hosts"`
}

type managedHostTokenGenerationEntry struct {
	Name        string `json:"name"`
	TokenSHA256 string `json:"token_sha256"`
}

func newManagedOperationBridge(config managedSetupRuntimeConfig, dataDir string, transaction managedTransactionBackend) (*managedOperationBridge, error) {
	pharos, err := newManagedPharosOperationClient(config.PharosOrigin, config.InternalToken, nil)
	if err != nil {
		return nil, err
	}
	store, err := newManagedOperationBridgeStore(filepath.Join(dataDir, "managed-operation-bridge.json"))
	if err != nil {
		return nil, err
	}
	if info, err := os.Stat(config.HostEnvelopeOutboxDir); err != nil || !info.IsDir() ||
		info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("managed host envelope outbox is unavailable")
	}
	if info, err := os.Stat(config.HostTokenGenerationDir); err != nil || !info.IsDir() ||
		info.Mode().Perm()&0027 != 0 {
		return nil, errors.New("managed host token generation is unavailable")
	}
	return &managedOperationBridge{
		transaction: transaction,
		pharos:      pharos,
		store:       store,
		outboxDir:   config.HostEnvelopeOutboxDir,
		tokens:      &managedHostTokenVerifier{root: config.HostTokenGenerationDir},
		now:         time.Now,
	}, nil
}

func newManagedPharosOperationClient(origin, token string, client *http.Client) (*managedPharosOperationClient, error) {
	parsed, err := parseManagedOrigin(origin)
	if err != nil || len(token) < 32 {
		return nil, errors.New("managed operation Pharos client is invalid")
	}
	if client == nil {
		client = &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &managedPharosOperationClient{
		origin: strings.TrimRight(parsed.String(), "/"),
		token:  token,
		client: client,
	}, nil
}

func newManagedOperationBridgeStore(path string) (*managedOperationBridgeStore, error) {
	document := managedOperationBridgeDocument{
		Schema:        managedOperationBridgeSchema,
		SchemaVersion: managedOperationBridgeVersion,
		Operations:    map[string]managedOperationBridgeRecord{},
	}
	raw, err := readBoundedPrivateFile(path, managedOperationBridgeMaxBytes)
	if err == nil {
		if decodeStrictJSON(raw, &document) != nil || validateManagedOperationBridgeDocument(document) != nil {
			return nil, errors.New("managed operation bridge state is invalid")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("managed operation bridge state is unavailable")
	}
	return &managedOperationBridgeStore{path: path, document: document}, nil
}

func (bridge *managedOperationBridge) Execute(ctx context.Context, accepted managedAcceptedIntent, importedValue []byte) (managedTransactionResult, error) {
	result, err := bridge.transaction.Execute(ctx, accepted, importedValue)
	if err != nil {
		return managedTransactionResult{}, err
	}
	if result.Generation == 0 || result.OperationRef != accepted.OperationRef {
		return managedTransactionResult{}, managedTransactionError("managed_operation_prepare_invalid")
	}
	now := bridge.now().Unix()
	record := managedOperationBridgeRecord{
		OperationRef:           accepted.OperationRef,
		OperationKind:          accepted.Intent.OperationKind,
		Source:                 accepted.Source,
		HostRef:                accepted.Intent.HostRef,
		ServiceRef:             accepted.Intent.ServiceRef,
		SlotRef:                accepted.Intent.SlotRef,
		DeclarationFingerprint: accepted.Intent.DeclarationFingerprint,
		DeliveryProfileRef:     accepted.Context.DeliveryProfileRef,
		ReloadProfileRef:       accepted.Context.ReloadProfileRef,
		HealthProfileRef:       accepted.Context.HealthProfileRef,
		Generation:             result.Generation,
		Phase:                  "prepared",
		CreatedAtUnixSeconds:   now,
		UpdatedAtUnixSeconds:   now,
		ValueReturned:          false,
	}
	if result.Phase == "completed" {
		existing, ok := bridge.store.get(record.OperationRef)
		if !ok || existing.Phase != "completed" || !sameManagedOperation(existing, record) {
			return managedTransactionResult{}, managedTransactionError("managed_operation_prepare_invalid")
		}
		return result, nil
	}
	if result.Phase != "prepared" {
		return managedTransactionResult{}, managedTransactionError("managed_operation_prepare_invalid")
	}
	if err := bridge.store.putPrepared(record); err != nil {
		_, _ = bridge.transaction.Rollback(ctx, record)
		return managedTransactionResult{}, managedTransactionError("managed_operation_state_unavailable")
	}
	if err := bridge.ensureRegistered(ctx, record.OperationRef); err != nil {
		return managedTransactionResult{}, err
	}
	result.Phase = "registered"
	result.ReasonCode = "managed_operation_registered"
	return result, nil
}

func (bridge *managedOperationBridge) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, record := range bridge.store.pendingRegistration() {
				retryContext, cancel := context.WithTimeout(ctx, 5*time.Second)
				_ = bridge.ensureRegistered(retryContext, record.OperationRef)
				cancel()
			}
			for _, record := range bridge.store.pendingReconciliation() {
				retryContext, cancel := context.WithTimeout(ctx, 5*time.Second)
				_, _ = bridge.reconcile(retryContext, managedHostReconcileRequest{
					Schema:        managedHostReconcileRequestSchema,
					SchemaVersion: 1,
					OperationRef:  record.OperationRef,
					HostRef:       record.HostRef,
					Generation:    record.Generation,
				})
				cancel()
			}
		}
	}
}

func (bridge *managedOperationBridge) ensureRegistered(ctx context.Context, operationRef string) error {
	record, ok := bridge.store.get(operationRef)
	if !ok {
		return managedTransactionError("managed_operation_unknown")
	}
	if record.Phase == "registered" || record.Phase == "completed" || record.Phase == "rolled_back" {
		return nil
	}
	if record.Phase != "prepared" {
		return managedTransactionError("managed_operation_state_invalid")
	}
	if _, err := bridge.pharos.register(ctx, record); err != nil {
		return managedTransactionError("managed_operation_registration_unavailable")
	}
	return bridge.store.setPhase(operationRef, "registered", bridge.now().Unix())
}

func (bridge *managedOperationBridge) reconcile(ctx context.Context, request managedHostReconcileRequest) (managedTransactionResult, error) {
	record, ok := bridge.store.get(request.OperationRef)
	if !ok || record.HostRef != request.HostRef || record.Generation != request.Generation {
		return managedTransactionResult{}, managedTransactionError("managed_operation_unknown")
	}
	status, err := bridge.pharos.status(ctx, record.OperationRef)
	if err != nil {
		return managedTransactionResult{}, managedTransactionError("managed_operation_status_unavailable")
	}
	if !status.matches(record) {
		return managedTransactionResult{}, managedTransactionError("managed_operation_status_invalid")
	}
	switch status.Operation.Phase {
	case "active":
		evidence, ok := status.externalEvidence()
		if !ok {
			return managedTransactionResult{}, managedTransactionError("managed_operation_evidence_invalid")
		}
		result, err := bridge.transaction.Finalize(ctx, record, evidence)
		if err != nil {
			return managedTransactionResult{}, err
		}
		if err := bridge.store.setPhase(record.OperationRef, "completed", bridge.now().Unix()); err != nil {
			return managedTransactionResult{}, managedTransactionError("managed_operation_state_unavailable")
		}
		return result, nil
	case "failed", "superseded":
		result, err := bridge.transaction.Rollback(ctx, record)
		if err != nil {
			return managedTransactionResult{}, err
		}
		if err := bridge.store.setPhase(record.OperationRef, "rolled_back", bridge.now().Unix()); err != nil {
			return managedTransactionResult{}, managedTransactionError("managed_operation_state_unavailable")
		}
		return result, nil
	default:
		return managedTransactionResult{}, managedTransactionError("managed_operation_not_terminal")
	}
}

func (bridge *managedOperationBridge) packetForHost(operationRef, hostRef string) ([]byte, error) {
	record, ok := bridge.store.get(operationRef)
	if !ok || record.HostRef != hostRef ||
		record.Phase != "prepared" && record.Phase != "registered" {
		return nil, managedTransactionError("managed_host_envelope_denied")
	}
	path := filepath.Join(bridge.outboxDir, operationRef+".json")
	raw, err := readBoundedRegularNoSymlink(path, managedHostOutboxMaxBytes, true)
	if err != nil {
		return nil, managedTransactionError("managed_host_envelope_unavailable")
	}
	var outbox managedHostOutboxRecord
	if decodeStrictJSON(raw, &outbox) != nil ||
		!outbox.matches(record, bridge.now().Unix()) {
		return nil, managedTransactionError("managed_host_envelope_invalid")
	}
	packet, err := base64.RawStdEncoding.DecodeString(outbox.PacketBase64)
	if err != nil || len(packet) == 0 || len(packet) > managedTransactionMaxFrameBytes*4 {
		return nil, managedTransactionError("managed_host_envelope_invalid")
	}
	return packet, nil
}

func (bridge *managedOperationBridge) hostAuthorized(hostRef, token string) bool {
	return bridge.tokens.authorized(hostRef, token)
}

func (client *managedPharosOperationClient) register(ctx context.Context, record managedOperationBridgeRecord) (managedPharosOperationStatus, error) {
	request := managedOperationReadyRequest{
		Schema:                 managedOperationReadySchema,
		SchemaVersion:          1,
		OperationRef:           record.OperationRef,
		OperationKind:          record.OperationKind,
		HostRef:                record.HostRef,
		ServiceRef:             record.ServiceRef,
		SlotRef:                record.SlotRef,
		DeclarationFingerprint: record.DeclarationFingerprint,
		Generation:             record.Generation,
		ValueReturned:          false,
	}
	return client.request(ctx, http.MethodPost, "/internal/managed-service-operations", request)
}

func (client *managedPharosOperationClient) status(ctx context.Context, operationRef string) (managedPharosOperationStatus, error) {
	if !validManagedRef("op_", operationRef) {
		return managedPharosOperationStatus{}, errors.New("managed operation reference invalid")
	}
	return client.request(ctx, http.MethodGet, "/internal/managed-service-operations/"+url.PathEscape(operationRef), nil)
}

func (client *managedPharosOperationClient) request(ctx context.Context, method, path string, body any) (managedPharosOperationStatus, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil || len(encoded) > 8*1024 {
			return managedPharosOperationStatus{}, errors.New("managed operation request invalid")
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, client.origin+path, reader)
	if err != nil {
		return managedPharosOperationStatus{}, err
	}
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.client.Do(request)
	if err != nil {
		return managedPharosOperationStatus{}, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 16*1024+1))
	if err != nil || len(raw) > 16*1024 || response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		return managedPharosOperationStatus{}, errors.New("managed operation response unavailable")
	}
	var status managedPharosOperationStatus
	if decodeStrictJSON(raw, &status) != nil || !status.valid() {
		return managedPharosOperationStatus{}, errors.New("managed operation response invalid")
	}
	return status, nil
}

func (status managedPharosOperationStatus) valid() bool {
	operation := status.Operation
	return status.Schema == managedOperationStatusSchema &&
		status.SchemaVersion == 1 &&
		!status.ValueReturned &&
		!operation.ValueReturned &&
		validManagedRef("op_", operation.OperationRef) &&
		(operation.OperationKind == "create" || operation.OperationKind == "replace") &&
		validManagedRef("host_", operation.HostRef) &&
		validManagedRef("svc_", operation.ServiceRef) &&
		validManagedRef("slot_", operation.SlotRef) &&
		validManagedRef("decl_", operation.DeclarationFingerprint) &&
		operation.Generation > 0 &&
		operation.CreatedAtUnixSeconds > 0 &&
		operation.UpdatedAtUnixSeconds >= operation.CreatedAtUnixSeconds &&
		validManagedOperationPhase(operation.Phase) &&
		validManagedPharosHealth(operation)
}

func validManagedPharosHealth(operation managedPharosOperationSummary) bool {
	if operation.Phase != "active" {
		return operation.Health == nil
	}
	health := operation.Health
	return health != nil &&
		health.Generation == operation.Generation &&
		health.Outcome == "healthy" &&
		health.HeartbeatObservedAtUnixSeconds > 0 &&
		health.ProcessObservedAtUnixSeconds > 0 &&
		health.ProbeObservedAtUnixSeconds > 0 &&
		health.AcceptedAtUnixSeconds > 0
}

func (status managedPharosOperationStatus) matches(record managedOperationBridgeRecord) bool {
	operation := status.Operation
	return status.valid() &&
		operation.OperationRef == record.OperationRef &&
		operation.OperationKind == record.OperationKind &&
		operation.HostRef == record.HostRef &&
		operation.ServiceRef == record.ServiceRef &&
		operation.SlotRef == record.SlotRef &&
		operation.DeclarationFingerprint == record.DeclarationFingerprint &&
		operation.Generation == record.Generation
}

func (status managedPharosOperationStatus) externalEvidence() (managedExternalActivationEvidence, bool) {
	health := status.Operation.Health
	if status.Operation.Phase != "active" || health == nil ||
		health.Generation != status.Operation.Generation || health.Outcome != "healthy" {
		return managedExternalActivationEvidence{}, false
	}
	evidence := managedExternalActivationEvidence{
		Generation:                     health.Generation,
		Materialized:                   true,
		ProcessState:                   "running",
		ProbeState:                     "healthy",
		HeartbeatObservedAtUnixSeconds: health.HeartbeatObservedAtUnixSeconds,
		ProcessObservedAtUnixSeconds:   health.ProcessObservedAtUnixSeconds,
		ProbeObservedAtUnixSeconds:     health.ProbeObservedAtUnixSeconds,
	}
	return evidence, validManagedExternalEvidence(&evidence)
}

func validManagedOperationPhase(value string) bool {
	switch value {
	case "install_pending", "installing", "reload_pending", "reloading", "verify_pending", "verifying", "active", "failed", "superseded":
		return true
	default:
		return false
	}
}

func (store *managedOperationBridgeStore) putPrepared(record managedOperationBridgeRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := validateManagedOperationBridgeRecord(record); err != nil {
		return err
	}
	if existing, ok := store.document.Operations[record.OperationRef]; ok {
		if !sameManagedOperation(existing, record) {
			return errors.New("managed operation bridge conflict")
		}
		return nil
	}
	if len(store.document.Operations) >= managedOperationBridgeMaxEntries {
		return errors.New("managed operation bridge capacity")
	}
	previous := cloneManagedOperationBridgeDocument(store.document)
	store.document.Operations[record.OperationRef] = record
	if err := atomicWriteManagedJSON(store.path, store.document); err != nil {
		store.document = previous
		return err
	}
	return nil
}

func (store *managedOperationBridgeStore) setPhase(operationRef, phase string, now int64) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.document.Operations[operationRef]
	if !ok || now <= 0 || !validManagedBridgePhase(phase) {
		return errors.New("managed operation bridge transition invalid")
	}
	if record.Phase == phase {
		return nil
	}
	if !validManagedBridgeTransition(record.Phase, phase) {
		return errors.New("managed operation bridge transition invalid")
	}
	previous := cloneManagedOperationBridgeDocument(store.document)
	record.Phase = phase
	record.UpdatedAtUnixSeconds = now
	store.document.Operations[operationRef] = record
	if err := atomicWriteManagedJSON(store.path, store.document); err != nil {
		store.document = previous
		return err
	}
	return nil
}

func (store *managedOperationBridgeStore) get(operationRef string) (managedOperationBridgeRecord, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.document.Operations[operationRef]
	return record, ok
}

func (store *managedOperationBridgeStore) pendingRegistration() []managedOperationBridgeRecord {
	store.mu.Lock()
	defer store.mu.Unlock()
	var pending []managedOperationBridgeRecord
	for _, record := range store.document.Operations {
		if record.Phase == "prepared" {
			pending = append(pending, record)
		}
	}
	sort.Slice(pending, func(left, right int) bool {
		return pending[left].OperationRef < pending[right].OperationRef
	})
	return pending
}

func (store *managedOperationBridgeStore) pendingReconciliation() []managedOperationBridgeRecord {
	store.mu.Lock()
	defer store.mu.Unlock()
	var pending []managedOperationBridgeRecord
	for _, record := range store.document.Operations {
		if record.Phase == "registered" {
			pending = append(pending, record)
		}
	}
	sort.Slice(pending, func(left, right int) bool {
		return pending[left].OperationRef < pending[right].OperationRef
	})
	return pending
}

func sameManagedOperation(left, right managedOperationBridgeRecord) bool {
	left.Phase = ""
	left.CreatedAtUnixSeconds = 0
	left.UpdatedAtUnixSeconds = 0
	right.Phase = ""
	right.CreatedAtUnixSeconds = 0
	right.UpdatedAtUnixSeconds = 0
	return left == right
}

func cloneManagedOperationBridgeDocument(document managedOperationBridgeDocument) managedOperationBridgeDocument {
	clone := managedOperationBridgeDocument{
		Schema:        document.Schema,
		SchemaVersion: document.SchemaVersion,
		Operations:    make(map[string]managedOperationBridgeRecord, len(document.Operations)),
	}
	for operationRef, record := range document.Operations {
		clone.Operations[operationRef] = record
	}
	return clone
}

func validateManagedOperationBridgeDocument(document managedOperationBridgeDocument) error {
	if document.Schema != managedOperationBridgeSchema ||
		document.SchemaVersion != managedOperationBridgeVersion ||
		document.Operations == nil ||
		len(document.Operations) > managedOperationBridgeMaxEntries {
		return errors.New("managed operation bridge document invalid")
	}
	for operationRef, record := range document.Operations {
		if operationRef != record.OperationRef || validateManagedOperationBridgeRecord(record) != nil {
			return errors.New("managed operation bridge document invalid")
		}
	}
	return nil
}

func validateManagedOperationBridgeRecord(record managedOperationBridgeRecord) error {
	if !validManagedRef("op_", record.OperationRef) ||
		record.OperationKind != "create" ||
		(record.Source != "generated" && record.Source != "import") ||
		!validManagedRef("host_", record.HostRef) ||
		!validManagedRef("svc_", record.ServiceRef) ||
		!validManagedRef("slot_", record.SlotRef) ||
		!validManagedRef("decl_", record.DeclarationFingerprint) ||
		!validManagedRef("delivery_", record.DeliveryProfileRef) ||
		!validManagedRef("reload_", record.ReloadProfileRef) ||
		!validManagedRef("health_", record.HealthProfileRef) ||
		record.Generation == 0 ||
		!validManagedBridgePhase(record.Phase) ||
		record.CreatedAtUnixSeconds <= 0 ||
		record.UpdatedAtUnixSeconds < record.CreatedAtUnixSeconds ||
		record.ValueReturned {
		return errors.New("managed operation bridge record invalid")
	}
	return nil
}

func validManagedBridgePhase(phase string) bool {
	switch phase {
	case "prepared", "registered", "completed", "rolled_back":
		return true
	default:
		return false
	}
}

func validManagedBridgeTransition(from, to string) bool {
	return from == "prepared" && (to == "registered" || to == "rolled_back") ||
		from == "registered" && (to == "completed" || to == "rolled_back")
}

func (record managedHostOutboxRecord) matches(bridge managedOperationBridgeRecord, now int64) bool {
	expectedHash, err := record.hash()
	return err == nil &&
		record.Schema == managedHostOutboxSchema &&
		record.SchemaVersion == 1 &&
		record.OperationRef == bridge.OperationRef &&
		record.OperationKind == bridge.OperationKind &&
		record.HostRef == bridge.HostRef &&
		record.ServiceRef == bridge.ServiceRef &&
		record.SlotRef == bridge.SlotRef &&
		validManagedRef("sec_", record.SecretRef) &&
		validManagedScopeRef(record.ScopeRef) &&
		record.DeclarationFingerprint == bridge.DeclarationFingerprint &&
		validManagedRef("env_", record.EnvelopeRef) &&
		record.Generation == bridge.Generation &&
		record.RevocationEpoch > 0 &&
		record.PreparedAtUnixSeconds > 0 &&
		record.ExpiresAtUnixSeconds > record.PreparedAtUnixSeconds &&
		now < record.ExpiresAtUnixSeconds &&
		!record.ValueReturned &&
		record.IntegrityHash == expectedHash
}

func validManagedScopeRef(value string) bool {
	if len(value) != 44 || !strings.HasPrefix(value, "scp_") {
		return false
	}
	for _, character := range value[4:] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func (record managedHostOutboxRecord) hash() (string, error) {
	record.IntegrityHash = ""
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (verifier *managedHostTokenVerifier) authorized(hostRef, token string) bool {
	if !validManagedRef("host_", hostRef) || len(token) < 32 || strings.IndexFunc(token, func(character rune) bool {
		return character <= ' '
	}) >= 0 {
		return false
	}
	currentRaw, err := readBoundedRegularNoSymlink(filepath.Join(verifier.root, "current"), managedTokenGenerationCurrentBytes, false)
	if err != nil {
		return false
	}
	generationID := strings.TrimSuffix(string(currentRaw), "\n")
	if !isLowerHexString(generationID, sha256.Size*2) {
		return false
	}
	raw, err := readBoundedRegularNoSymlink(
		filepath.Join(verifier.root, "generation-"+generationID+".json"),
		managedTokenGenerationMaxBytes,
		false,
	)
	if err != nil {
		return false
	}
	var generation managedHostTokenGeneration
	if decodeStrictJSON(raw, &generation) != nil ||
		generation.Schema != managedHostTokenGenerationSchema ||
		generation.Generation != generationID ||
		len(generation.Hosts) == 0 ||
		len(generation.Hosts) > 1024 {
		return false
	}
	sort.Slice(generation.Hosts, func(left, right int) bool {
		return generation.Hosts[left].Name < generation.Hosts[right].Name
	})
	hasher := sha256.New()
	hasher.Write([]byte(managedHostTokenGenerationSchema))
	hasher.Write([]byte{0})
	var expected string
	last := ""
	for _, entry := range generation.Hosts {
		if entry.Name <= last || !validManagedTokenSubject(entry.Name) ||
			!isLowerHexString(entry.TokenSHA256, sha256.Size*2) {
			return false
		}
		last = entry.Name
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(entry.Name)))
		hasher.Write(length[:])
		hasher.Write([]byte(entry.Name))
		hasher.Write([]byte(entry.TokenSHA256))
		if entry.Name == hostRef {
			expected = entry.TokenSHA256
		}
	}
	if hex.EncodeToString(hasher.Sum(nil)) != generationID || expected == "" {
		return false
	}
	actual := sha256.Sum256([]byte(token))
	return constantTimeStringEqual(expected, hex.EncodeToString(actual[:]))
}

func validManagedTokenSubject(value string) bool {
	return validManagedRef("host_", value) || validHostTokenName(value)
}

func validHostTokenName(value string) bool {
	if value == "" || len(value) > 253 || strings.ToLower(value) != value {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func constantTimeStringEqual(left, right string) bool {
	maximum := len(left)
	if len(right) > maximum {
		maximum = len(right)
	}
	difference := len(left) ^ len(right)
	for index := 0; index < maximum; index++ {
		var leftByte, rightByte byte
		if index < len(left) {
			leftByte = left[index]
		}
		if index < len(right) {
			rightByte = right[index]
		}
		difference |= int(leftByte ^ rightByte)
	}
	return difference == 0
}

func readBoundedRegularNoSymlink(path string, maximum int64, private bool) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() ||
		before.Size() <= 0 || before.Size() > maximum ||
		private && before.Mode().Perm()&0077 != 0 ||
		!private && before.Mode().Perm()&0027 != 0 {
		return nil, errors.New("managed file contract invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("managed file changed during open")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, errors.New("managed file contract invalid")
	}
	return raw, nil
}
