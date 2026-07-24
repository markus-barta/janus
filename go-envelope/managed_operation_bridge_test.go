package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeManagedTransactionBackend struct {
	executeResult managedTransactionResult
	executeHook   func(managedAcceptedIntent, []byte)
	finalizeCount int
	rollbackCount int
	purgeCount    int
}

func (fake *fakeManagedTransactionBackend) Execute(_ context.Context, accepted managedAcceptedIntent, value []byte) (managedTransactionResult, error) {
	if fake.executeHook != nil {
		fake.executeHook(accepted, value)
	}
	return fake.executeResult, nil
}

func (fake *fakeManagedTransactionBackend) Finalize(_ context.Context, record managedOperationBridgeRecord, evidence managedExternalActivationEvidence) (managedTransactionResult, error) {
	fake.finalizeCount++
	return managedTransactionResult{
		OperationRef: record.OperationRef,
		SecretRef:    "sec_0123456789abcdef",
		Mode:         record.Source,
		Generation:   evidence.Generation,
		Phase:        "completed",
		ReasonCode:   "entry_external_activation_ok",
	}, nil
}

func (fake *fakeManagedTransactionBackend) FinalizeRemoval(_ context.Context, record managedOperationBridgeRecord, evidence managedExternalRemovalEvidence) (managedTransactionResult, error) {
	fake.finalizeCount++
	return managedTransactionResult{
		OperationRef: record.OperationRef,
		SecretRef:    "sec_0123456789abcdef",
		Mode:         record.Source,
		Generation:   evidence.Generation,
		Phase:        "completed",
		ReasonCode:   "entry_removal_quarantined",
	}, nil
}

func (fake *fakeManagedTransactionBackend) Rollback(_ context.Context, record managedOperationBridgeRecord) (managedTransactionResult, error) {
	fake.rollbackCount++
	return managedTransactionResult{
		OperationRef: record.OperationRef,
		SecretRef:    "sec_0123456789abcdef",
		Mode:         record.Source,
		Generation:   record.Generation,
		Phase:        "rolled_back",
		ReasonCode:   "entry_rollback_ok",
	}, nil
}

func (fake *fakeManagedTransactionBackend) Purge(_ context.Context, record managedOperationBridgeRecord) (managedTransactionResult, error) {
	fake.purgeCount++
	return managedTransactionResult{
		OperationRef: record.OperationRef,
		SecretRef:    "sec_0123456789abcdef",
		Mode:         record.Source,
		Generation:   record.Generation,
		Phase:        "destroyed",
		ReasonCode:   "entry_removal_destroyed",
	}, nil
}

func managedBridgeRecord(operationRef string) managedOperationBridgeRecord {
	return managedOperationBridgeRecord{
		OperationRef:           operationRef,
		OperationKind:          "create",
		Source:                 "import",
		HostRef:                "host_58f36c72a91e",
		ServiceRef:             "svc_0bca8d31f7e2",
		SlotRef:                "slot_49c0e8a17d63",
		DeclarationFingerprint: "decl_1e0775870c7d987e",
		DeliveryProfileRef:     "delivery_2d7a0f63c951",
		ReloadProfileRef:       "reload_65bc19f3a087",
		HealthProfileRef:       "health_918d0ce7b4a2",
		Generation:             1,
		Phase:                  "prepared",
		CreatedAtUnixSeconds:   1_800_000_000,
		UpdatedAtUnixSeconds:   1_800_000_000,
		ValueReturned:          false,
	}
}

func writeManagedHostTokenGeneration(t *testing.T, root, hostRef, token string) {
	t.Helper()
	tokenDigest := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(tokenDigest[:])
	hasher := sha256.New()
	hasher.Write([]byte(managedHostTokenGenerationSchema))
	hasher.Write([]byte{0})
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(hostRef)))
	hasher.Write(length[:])
	hasher.Write([]byte(hostRef))
	hasher.Write([]byte(tokenHash))
	generationID := hex.EncodeToString(hasher.Sum(nil))
	document := managedHostTokenGeneration{
		Schema:     managedHostTokenGenerationSchema,
		Generation: generationID,
		Hosts: []managedHostTokenGenerationEntry{{
			Name:        hostRef,
			TokenSHA256: tokenHash,
		}},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "generation-"+generationID+".json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "current"), []byte(generationID+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestManagedBridgeDeliversOnlyBoundCiphertextToExactHost(t *testing.T) {
	root := t.TempDir()
	outboxDir := filepath.Join(root, "outbox")
	tokenDir := filepath.Join(root, "tokens")
	if err := os.Mkdir(outboxDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tokenDir, 0700); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("agent-token-", 4)
	record := managedBridgeRecord("op_10000001")
	writeManagedHostTokenGeneration(t, tokenDir, record.HostRef, token)
	store, err := newManagedOperationBridgeStore(filepath.Join(root, "bridge.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.putPrepared(record); err != nil {
		t.Fatal(err)
	}
	packet := []byte("synthetic-ciphertext-packet")
	outbox := managedHostOutboxRecord{
		Schema:                 managedHostOutboxSchema,
		SchemaVersion:          1,
		OperationRef:           record.OperationRef,
		OperationKind:          record.OperationKind,
		HostRef:                record.HostRef,
		ServiceRef:             record.ServiceRef,
		SlotRef:                record.SlotRef,
		SecretRef:              "sec_0123456789abcdef",
		ScopeRef:               "scp_0123456789abcdef0123456789abcdef01234567",
		DeclarationFingerprint: record.DeclarationFingerprint,
		EnvelopeRef:            "env_0123456789abcdef",
		Generation:             record.Generation,
		RevocationEpoch:        1,
		PreparedAtUnixSeconds:  1_800_000_000,
		ExpiresAtUnixSeconds:   1_800_000_900,
		PacketBase64:           base64.RawStdEncoding.EncodeToString(packet),
		ValueReturned:          false,
	}
	outbox.IntegrityHash, err = outbox.hash()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(outbox)
	if err := os.WriteFile(filepath.Join(outboxDir, record.OperationRef+".json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	bridge := &managedOperationBridge{
		store:     store,
		outboxDir: outboxDir,
		tokens:    &managedHostTokenVerifier{root: tokenDir},
		now:       func() time.Time { return time.Unix(1_800_000_100, 0) },
	}
	if !bridge.hostAuthorized(record.HostRef, token) ||
		bridge.hostAuthorized("host_aaaaaaaaaaaaaaaa", token) ||
		bridge.hostAuthorized(record.HostRef, token+"wrong") {
		t.Fatal("host-ref token binding failed")
	}
	got, err := bridge.packetForHost(record.OperationRef, record.HostRef)
	if err != nil || string(got) != string(packet) {
		t.Fatalf("exact ciphertext packet was not delivered: %q %v", got, err)
	}
	if _, err := bridge.packetForHost(record.OperationRef, "host_aaaaaaaaaaaaaaaa"); err == nil {
		t.Fatal("cross-host packet request was admitted")
	}

	app := newTestApp(t)
	app.managedBridge = bridge
	request := httptest.NewRequest(
		http.MethodGet,
		"/internal/managed-service-host-envelopes/"+record.HostRef+"/"+record.OperationRef,
		nil,
	)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		response.Header().Get("Cache-Control") != "no-store, no-transform" ||
		response.Body.String() != string(packet) {
		t.Fatalf("unexpected host envelope response: %d %q", response.Code, response.Body.String())
	}
}

func TestManagedOutboxIntegrityHashMatchesRustContract(t *testing.T) {
	record := managedHostOutboxRecord{
		Schema:                 managedHostOutboxSchema,
		SchemaVersion:          1,
		OperationRef:           "op_0123456789abcdef",
		OperationKind:          "create",
		HostRef:                "host_0123456789abcdef",
		ServiceRef:             "svc_0123456789abcdef",
		SlotRef:                "slot_0123456789abcdef",
		SecretRef:              "sec_0123456789abcdef",
		ScopeRef:               "scp_0123456789abcdef0123456789abcdef01234567",
		DeclarationFingerprint: "decl_0123456789abcdef",
		EnvelopeRef:            "env_0123456789abcdef",
		Generation:             1,
		RevocationEpoch:        1,
		PreparedAtUnixSeconds:  1_800_000_000,
		ExpiresAtUnixSeconds:   1_800_000_900,
		PacketBase64:           "cGFja2V0",
		ValueReturned:          false,
	}
	hash, err := record.hash()
	if err != nil {
		t.Fatal(err)
	}
	if hash != "7da188178df0cd5c18c3340c6d7474a8d89d630dbcfdba3ca004ffd8039b21aa" {
		t.Fatalf("Go outbox hash drifted from Rust: %s", hash)
	}
}

func TestManagedBridgeReconciliationIsTerminalAndIdempotent(t *testing.T) {
	root := t.TempDir()
	store, err := newManagedOperationBridgeStore(filepath.Join(root, "bridge.json"))
	if err != nil {
		t.Fatal(err)
	}
	record := managedBridgeRecord("op_20000001")
	if err := store.putPrepared(record); err != nil {
		t.Fatal(err)
	}
	if err := store.setPhase(record.OperationRef, "registered", 1_800_000_001); err != nil {
		t.Fatal(err)
	}
	statusServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet ||
			request.URL.Path != "/internal/managed-service-operations/"+record.OperationRef ||
			request.Header.Get("Authorization") != "Bearer "+strings.Repeat("i", 32) {
			t.Errorf("unexpected Pharos status request: %s %s", request.Method, request.URL.Path)
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(managedPharosOperationStatus{
			Schema:        managedOperationStatusSchema,
			SchemaVersion: 1,
			Operation: managedPharosOperationSummary{
				OperationRef:           record.OperationRef,
				OperationKind:          record.OperationKind,
				HostRef:                record.HostRef,
				ServiceRef:             record.ServiceRef,
				SlotRef:                record.SlotRef,
				DeclarationFingerprint: record.DeclarationFingerprint,
				Generation:             record.Generation,
				Phase:                  "active",
				CreatedAtUnixSeconds:   1_800_000_000,
				UpdatedAtUnixSeconds:   1_800_000_010,
				Health: &managedPharosHealthSummary{
					Generation:                     record.Generation,
					Outcome:                        "healthy",
					HeartbeatObservedAtUnixSeconds: 1_800_000_009,
					ProcessObservedAtUnixSeconds:   1_800_000_009,
					ProbeObservedAtUnixSeconds:     1_800_000_009,
					AcceptedAtUnixSeconds:          1_800_000_010,
				},
				ValueReturned: false,
			},
			ValueReturned: false,
		})
	}))
	defer statusServer.Close()
	pharos, err := newManagedPharosOperationClient(
		statusServer.URL,
		strings.Repeat("i", 32),
		statusServer.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	backend := &fakeManagedTransactionBackend{}
	bridge := &managedOperationBridge{
		transaction: backend,
		pharos:      pharos,
		store:       store,
		now:         func() time.Time { return time.Unix(1_800_000_011, 0) },
	}
	request := managedHostReconcileRequest{
		Schema:        managedHostReconcileRequestSchema,
		SchemaVersion: 1,
		OperationRef:  record.OperationRef,
		HostRef:       record.HostRef,
		Generation:    record.Generation,
	}
	for range 2 {
		result, err := bridge.reconcile(context.Background(), request)
		if err != nil || result.Phase != "completed" || result.ValueReturned {
			t.Fatalf("terminal reconciliation failed: %#v %v", result, err)
		}
	}
	if backend.finalizeCount != 2 || backend.rollbackCount != 0 {
		t.Fatalf("duplicate reconciliation was not idempotent: %#v", backend)
	}
	completed, ok := store.get(record.OperationRef)
	if !ok || completed.Phase != "completed" {
		t.Fatalf("bridge did not persist completion: %#v", completed)
	}
	backend.executeResult = managedTransactionResult{
		OperationRef: record.OperationRef,
		SecretRef:    "sec_0123456789abcdef",
		Mode:         record.Source,
		Generation:   record.Generation,
		Phase:        "completed",
		ReasonCode:   "entry_external_activation_ok",
	}
	replayed, err := bridge.Execute(context.Background(), managedAcceptedIntent{
		Intent: managedSetupIntent{
			OperationKind:          record.OperationKind,
			HostRef:                record.HostRef,
			ServiceRef:             record.ServiceRef,
			SlotRef:                record.SlotRef,
			DeclarationFingerprint: record.DeclarationFingerprint,
		},
		Source:       record.Source,
		OperationRef: record.OperationRef,
		Context: managedDeclarationContext{
			DeliveryProfileRef: record.DeliveryProfileRef,
			ReloadProfileRef:   record.ReloadProfileRef,
			HealthProfileRef:   record.HealthProfileRef,
		},
	}, []byte("synthetic-replay"))
	if err != nil || replayed.Phase != "completed" {
		t.Fatalf("completed operation replay was not idempotent: %#v %v", replayed, err)
	}
}

func TestManagedBridgeReplacementRollbackIsBoundAndIdempotent(t *testing.T) {
	root := t.TempDir()
	store, err := newManagedOperationBridgeStore(filepath.Join(root, "bridge.json"))
	if err != nil {
		t.Fatal(err)
	}
	record := managedBridgeRecord("op_20000002")
	record.OperationKind = "replace"
	record.Generation = 2
	if err := store.putPrepared(record); err != nil {
		t.Fatal(err)
	}
	if err := store.setPhase(record.OperationRef, "registered", 1_800_000_001); err != nil {
		t.Fatal(err)
	}
	statusServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(managedPharosOperationStatus{
			Schema:        managedOperationStatusSchema,
			SchemaVersion: 1,
			Operation: managedPharosOperationSummary{
				OperationRef:           record.OperationRef,
				OperationKind:          record.OperationKind,
				HostRef:                record.HostRef,
				ServiceRef:             record.ServiceRef,
				SlotRef:                record.SlotRef,
				DeclarationFingerprint: record.DeclarationFingerprint,
				Generation:             record.Generation,
				Phase:                  "rolled_back",
				CreatedAtUnixSeconds:   1_800_000_000,
				UpdatedAtUnixSeconds:   1_800_000_010,
				Rollback: &managedPharosRollbackSummary{
					RestoredGeneration:             1,
					Outcome:                        "healthy",
					HeartbeatObservedAtUnixSeconds: 1_800_000_009,
					ProcessObservedAtUnixSeconds:   1_800_000_009,
					ProbeObservedAtUnixSeconds:     1_800_000_009,
					AcceptedAtUnixSeconds:          1_800_000_010,
				},
				ValueReturned: false,
			},
			ValueReturned: false,
		})
	}))
	defer statusServer.Close()
	pharos, err := newManagedPharosOperationClient(
		statusServer.URL,
		strings.Repeat("i", 32),
		statusServer.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	backend := &fakeManagedTransactionBackend{}
	bridge := &managedOperationBridge{
		transaction: backend,
		pharos:      pharos,
		store:       store,
		now:         func() time.Time { return time.Unix(1_800_000_011, 0) },
	}
	request := managedHostReconcileRequest{
		Schema:        managedHostReconcileRequestSchema,
		SchemaVersion: 1,
		OperationRef:  record.OperationRef,
		HostRef:       record.HostRef,
		Generation:    record.Generation,
	}
	for range 2 {
		result, err := bridge.reconcile(context.Background(), request)
		if err != nil || result.Phase != "rolled_back" || result.ValueReturned {
			t.Fatalf("replacement rollback reconciliation failed: %#v %v", result, err)
		}
	}
	if backend.rollbackCount != 2 || backend.finalizeCount != 0 {
		t.Fatalf("replacement rollback was not idempotently dispatched: %#v", backend)
	}
	rolledBack, ok := store.get(record.OperationRef)
	if !ok || rolledBack.Phase != "rolled_back" {
		t.Fatalf("bridge did not persist replacement rollback: %#v", rolledBack)
	}
}

func TestManagedBridgeRejectsConcurrentOperationsForOneSlot(t *testing.T) {
	store, err := newManagedOperationBridgeStore(filepath.Join(t.TempDir(), "bridge.json"))
	if err != nil {
		t.Fatal(err)
	}
	first := managedBridgeRecord("op_20000003")
	if err := store.putPrepared(first); err != nil {
		t.Fatal(err)
	}
	second := managedBridgeRecord("op_20000004")
	second.OperationKind = "replace"
	second.Generation = 2
	if err := store.putPrepared(second); err == nil {
		t.Fatal("concurrent create/replace operations for one slot were admitted")
	}
	if _, ok := store.get(second.OperationRef); ok {
		t.Fatal("rejected slot conflict was persisted")
	}
}

func TestManagedBridgeFailedWriteRestoresInMemoryState(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if err := os.Mkdir(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := newManagedOperationBridgeStore(filepath.Join(stateDir, "bridge.json"))
	if err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	store.path = filepath.Join(blocker, "bridge.json")
	record := managedBridgeRecord("op_30000001")
	if err := store.putPrepared(record); err == nil {
		t.Fatal("unwritable durable state unexpectedly succeeded")
	}
	if _, ok := store.get(record.OperationRef); ok {
		t.Fatal("failed durable write mutated in-memory operation state")
	}
}

func TestManagedBrowserImportRegistersHostDeliveryAndFinalizesWithoutValueReturn(t *testing.T) {
	const canary = "SENSITIVE_E2E_IMPORT_CANARY_361"
	app, _, _, session, sessionCookie, proofCookie := managedIngressFixture(t, "import")
	root := t.TempDir()
	outboxDir := filepath.Join(root, "outbox")
	tokenDir := filepath.Join(root, "tokens")
	if err := os.Mkdir(outboxDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tokenDir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := newManagedOperationBridgeStore(filepath.Join(root, "bridge.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	phase := "install_pending"
	var registeredBody []byte
	statusServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			body, readErr := io.ReadAll(request.Body)
			if readErr != nil {
				t.Error(readErr)
			}
			registeredBody = append([]byte(nil), body...)
		}
		response.Header().Set("Content-Type", "application/json")
		summary := managedPharosOperationSummary{
			OperationRef:           managedTestOpRef,
			OperationKind:          "create",
			HostRef:                "host_0123456789abcdef",
			ServiceRef:             "svc_0123456789abcdef",
			SlotRef:                "slot_0123456789abcdef",
			DeclarationFingerprint: "decl_0123456789abcdef",
			Generation:             1,
			Phase:                  phase,
			CreatedAtUnixSeconds:   now.Add(-time.Second).Unix(),
			UpdatedAtUnixSeconds:   now.Unix(),
			ValueReturned:          false,
		}
		if phase == "active" {
			summary.Health = &managedPharosHealthSummary{
				Generation:                     1,
				Outcome:                        "healthy",
				HeartbeatObservedAtUnixSeconds: now.Unix(),
				ProcessObservedAtUnixSeconds:   now.Unix(),
				ProbeObservedAtUnixSeconds:     now.Unix(),
				AcceptedAtUnixSeconds:          now.Unix(),
			}
		}
		if request.Method == http.MethodPost {
			response.WriteHeader(http.StatusCreated)
		}
		_ = json.NewEncoder(response).Encode(managedPharosOperationStatus{
			Schema:        managedOperationStatusSchema,
			SchemaVersion: 1,
			Operation:     summary,
			ValueReturned: false,
		})
	}))
	defer statusServer.Close()
	pharos, err := newManagedPharosOperationClient(
		statusServer.URL,
		strings.Repeat("i", 32),
		statusServer.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	packet := []byte("synthetic-encrypted-host-packet")
	valueObserved := false
	backend := &fakeManagedTransactionBackend{
		executeResult: managedTransactionResult{
			OperationRef: managedTestOpRef,
			SecretRef:    managedTestSecretRef,
			Mode:         "import",
			Generation:   1,
			Phase:        "prepared",
			ReasonCode:   "entry_delivery_prepared",
		},
		executeHook: func(accepted managedAcceptedIntent, value []byte) {
			valueObserved = string(value) == canary
			outbox := managedHostOutboxRecord{
				Schema:                 managedHostOutboxSchema,
				SchemaVersion:          1,
				OperationRef:           accepted.OperationRef,
				OperationKind:          accepted.Intent.OperationKind,
				HostRef:                accepted.Intent.HostRef,
				ServiceRef:             accepted.Intent.ServiceRef,
				SlotRef:                accepted.Intent.SlotRef,
				SecretRef:              managedTestSecretRef,
				ScopeRef:               "scp_0123456789abcdef0123456789abcdef01234567",
				DeclarationFingerprint: accepted.Intent.DeclarationFingerprint,
				EnvelopeRef:            "env_0123456789abcdef",
				Generation:             1,
				RevocationEpoch:        1,
				PreparedAtUnixSeconds:  now.Add(-time.Second).Unix(),
				ExpiresAtUnixSeconds:   now.Add(time.Minute).Unix(),
				PacketBase64:           base64.RawStdEncoding.EncodeToString(packet),
				ValueReturned:          false,
			}
			outbox.IntegrityHash, err = outbox.hash()
			if err != nil {
				t.Error(err)
				return
			}
			raw, encodeErr := json.Marshal(outbox)
			if encodeErr != nil {
				t.Error(encodeErr)
				return
			}
			if writeErr := os.WriteFile(
				filepath.Join(outboxDir, accepted.OperationRef+".json"),
				raw,
				0600,
			); writeErr != nil {
				t.Error(writeErr)
			}
		},
	}
	bridge := &managedOperationBridge{
		transaction: backend,
		pharos:      pharos,
		store:       store,
		outboxDir:   outboxDir,
		tokens:      &managedHostTokenVerifier{root: tokenDir},
		now:         func() time.Time { return now },
	}
	app.managedTxn = bridge
	app.managedBridge = bridge
	formPrefix := "csrf_token=" + app.csrfToken(session) +
		"&intent_ref=" + managedTestIntentRef +
		"&source=import&secret_value="
	body := formPrefix + canary
	request := managedRequest(
		t,
		app,
		session,
		sessionCookie,
		proofCookie,
		strings.NewReader(body),
		int64(len(body)),
	)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "https://pharos.barta.cm/managed-service/operations/"+managedTestOpRef ||
		!valueObserved {
		t.Fatalf("browser handoff failed: status=%d location=%q observed=%t", response.Code, response.Header().Get("Location"), valueObserved)
	}
	record, ok := store.get(managedTestOpRef)
	if !ok || record.Phase != "registered" || record.ValueReturned {
		t.Fatalf("operation was not durably registered: %#v", record)
	}
	bridgeState, err := os.ReadFile(filepath.Join(root, "bridge.json"))
	if err != nil {
		t.Fatal(err)
	}
	for label, captured := range map[string][]byte{
		"browser response": response.Body.Bytes(),
		"Pharos request":   registeredBody,
		"bridge state":     bridgeState,
	} {
		if strings.Contains(string(captured), canary) {
			t.Fatalf("%s retained the synthetic value", label)
		}
	}
	delivered, err := bridge.packetForHost(managedTestOpRef, "host_0123456789abcdef")
	if err != nil || string(delivered) != string(packet) {
		t.Fatalf("host packet handoff failed: %q %v", delivered, err)
	}
	phase = "active"
	result, err := bridge.reconcile(context.Background(), managedHostReconcileRequest{
		Schema:        managedHostReconcileRequestSchema,
		SchemaVersion: 1,
		OperationRef:  managedTestOpRef,
		HostRef:       "host_0123456789abcdef",
		Generation:    1,
	})
	if err != nil || result.Phase != "completed" || backend.finalizeCount != 1 {
		t.Fatalf("fresh health did not finalize central activation: %#v %v", result, err)
	}
}

func TestManagedBrowserRemovalCarriesNoValueQuarantinesAndPurgesOnlyWhenDue(t *testing.T) {
	const forbiddenCanary = "SENSITIVE_REMOVAL_VALUE_MUST_NEVER_EXIST_363"
	app, _, _, session, sessionCookie, proofCookie := managedIngressFixture(t, "remove")
	root := t.TempDir()
	store, err := newManagedOperationBridgeStore(filepath.Join(root, "bridge.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	deadline := now.Add(managedRemovalRecoveryWindow).Unix()
	phase := "removal_pending"
	var registeredBody []byte
	statusServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			var readErr error
			registeredBody, readErr = io.ReadAll(request.Body)
			if readErr != nil {
				t.Error(readErr)
			}
		}
		summary := managedPharosOperationSummary{
			OperationRef:              managedTestOpRef,
			OperationKind:             "remove",
			HostRef:                   "host_0123456789abcdef",
			ServiceRef:                "svc_0123456789abcdef",
			SlotRef:                   "slot_0123456789abcdef",
			DeclarationFingerprint:    "decl_0123456789abcdef",
			Generation:                1,
			PurgeNotBeforeUnixSeconds: deadline,
			Phase:                     phase,
			CreatedAtUnixSeconds:      now.Unix(),
			UpdatedAtUnixSeconds:      now.Add(10 * time.Second).Unix(),
			ValueReturned:             false,
		}
		if phase == "removed" {
			summary.Removal = &managedPharosRemovalSummary{
				Generation:                     1,
				Outcome:                        "healthy",
				HeartbeatObservedAtUnixSeconds: now.Add(9 * time.Second).Unix(),
				ProcessObservedAtUnixSeconds:   now.Add(9 * time.Second).Unix(),
				CacheObservedAtUnixSeconds:     now.Add(9 * time.Second).Unix(),
				AcceptedAtUnixSeconds:          now.Add(10 * time.Second).Unix(),
			}
		}
		response.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPost {
			response.WriteHeader(http.StatusCreated)
		}
		_ = json.NewEncoder(response).Encode(managedPharosOperationStatus{
			Schema:        managedOperationStatusSchema,
			SchemaVersion: 1,
			Operation:     summary,
			ValueReturned: false,
		})
	}))
	defer statusServer.Close()
	pharos, err := newManagedPharosOperationClient(
		statusServer.URL,
		strings.Repeat("i", 32),
		statusServer.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	valueObserved := false
	backend := &fakeManagedTransactionBackend{
		executeResult: managedTransactionResult{
			OperationRef: managedTestOpRef,
			SecretRef:    managedTestSecretRef,
			Mode:         "remove",
			Generation:   1,
			Phase:        "prepared",
			ReasonCode:   "entry_removal_prepared",
		},
		executeHook: func(accepted managedAcceptedIntent, value []byte) {
			valueObserved = len(value) != 0 ||
				accepted.Intent.OperationKind != "remove" ||
				accepted.Source != "remove" ||
				accepted.Context.BindingState != "detached" ||
				accepted.Context.DetachProfileRef != "detach_0123456789abcdef"
		},
	}
	bridge := &managedOperationBridge{
		transaction: backend,
		pharos:      pharos,
		store:       store,
		outboxDir:   filepath.Join(root, "outbox-does-not-exist"),
		now:         func() time.Time { return now },
	}
	app.managedTxn = bridge
	app.managedBridge = bridge
	form := "csrf_token=" + app.csrfToken(session) +
		"&intent_ref=" + managedTestIntentRef +
		"&source=remove&secret_value="
	request := managedRequest(
		t,
		app,
		session,
		sessionCookie,
		proofCookie,
		strings.NewReader(form),
		int64(len(form)),
	)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || valueObserved {
		t.Fatalf("value-free removal handoff failed: status=%d value_observed=%t", response.Code, valueObserved)
	}
	record, ok := store.get(managedTestOpRef)
	if !ok ||
		record.OperationKind != "remove" ||
		record.Source != "remove" ||
		record.DetachProfileRef != "detach_0123456789abcdef" ||
		record.PurgeNotBeforeUnixSeconds != deadline ||
		record.Phase != "registered" ||
		record.ValueReturned {
		t.Fatalf("removal was not durably and exactly bound: %#v", record)
	}
	for label, captured := range map[string][]byte{
		"browser response": response.Body.Bytes(),
		"Pharos request":   registeredBody,
	} {
		if strings.Contains(string(captured), forbiddenCanary) {
			t.Fatalf("%s retained a forbidden removal value", label)
		}
	}
	var ready managedOperationReadyRequest
	if decodeStrictJSON(registeredBody, &ready) != nil ||
		ready.OperationKind != "remove" ||
		ready.PurgeNotBeforeUnixSeconds != deadline ||
		ready.ValueReturned {
		t.Fatalf("Pharos removal registration drifted: %#v", ready)
	}
	if _, err := bridge.packetForHost(managedTestOpRef, record.HostRef); err == nil {
		t.Fatal("removal unexpectedly exposed a host packet")
	}

	phase = "removed"
	result, err := bridge.reconcile(context.Background(), managedHostReconcileRequest{
		Schema:        managedHostReconcileRequestSchema,
		SchemaVersion: 1,
		OperationRef:  managedTestOpRef,
		HostRef:       record.HostRef,
		Generation:    record.Generation,
	})
	if err != nil ||
		result.Phase != "completed" ||
		result.ValueReturned ||
		backend.finalizeCount != 1 {
		t.Fatalf("fresh removal evidence did not quarantine centrally: %#v %v", result, err)
	}
	quarantined, ok := store.get(managedTestOpRef)
	if !ok || quarantined.Phase != "quarantined" {
		t.Fatalf("removal quarantine was not persisted: %#v", quarantined)
	}
	if due := store.pendingPurge(deadline - 1); len(due) != 0 {
		t.Fatalf("removal became purgeable before its deadline: %#v", due)
	}
	due := store.pendingPurge(deadline)
	if len(due) != 1 || due[0].OperationRef != managedTestOpRef {
		t.Fatalf("removal was not purgeable at its exact boundary: %#v", due)
	}
	purged, err := backend.Purge(context.Background(), due[0])
	if err != nil || purged.Phase != "destroyed" || purged.ValueReturned {
		t.Fatalf("due purge failed: %#v %v", purged, err)
	}
	if err := store.setPhase(managedTestOpRef, "destroyed", deadline); err != nil {
		t.Fatal(err)
	}
	if backend.rollbackCount != 0 || backend.purgeCount != 1 {
		t.Fatalf("removal used an unsafe recovery path: %#v", backend)
	}

	backend.executeResult = purged
	replayed, err := bridge.Execute(context.Background(), managedAcceptedIntent{
		Intent: managedSetupIntent{
			OperationKind:          "remove",
			HostRef:                record.HostRef,
			ServiceRef:             record.ServiceRef,
			SlotRef:                record.SlotRef,
			DeclarationFingerprint: record.DeclarationFingerprint,
		},
		Source:       "remove",
		OperationRef: record.OperationRef,
		Context: managedDeclarationContext{
			DeliveryProfileRef: record.DeliveryProfileRef,
			ReloadProfileRef:   record.ReloadProfileRef,
			HealthProfileRef:   record.HealthProfileRef,
			BindingState:       "detached",
			DetachProfileRef:   record.DetachProfileRef,
		},
	}, nil)
	if err != nil || replayed.Phase != "destroyed" {
		t.Fatalf("destroyed removal replay was not idempotent: %#v %v", replayed, err)
	}
}

func TestManagedFailedRemovalRequiresReviewAndNeverRestoresAutomatically(t *testing.T) {
	store, err := newManagedOperationBridgeStore(filepath.Join(t.TempDir(), "bridge.json"))
	if err != nil {
		t.Fatal(err)
	}
	record := managedBridgeRecord("op_removefailure01")
	record.OperationKind = "remove"
	record.Source = "remove"
	record.DetachProfileRef = "detach_0123456789abcdef"
	record.PurgeNotBeforeUnixSeconds = 1_800_086_400
	if err := store.putPrepared(record); err != nil {
		t.Fatal(err)
	}
	if err := store.setPhase(record.OperationRef, "registered", 1_800_000_001); err != nil {
		t.Fatal(err)
	}
	statusServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(managedPharosOperationStatus{
			Schema:        managedOperationStatusSchema,
			SchemaVersion: 1,
			Operation: managedPharosOperationSummary{
				OperationRef:              record.OperationRef,
				OperationKind:             record.OperationKind,
				HostRef:                   record.HostRef,
				ServiceRef:                record.ServiceRef,
				SlotRef:                   record.SlotRef,
				DeclarationFingerprint:    record.DeclarationFingerprint,
				Generation:                record.Generation,
				PurgeNotBeforeUnixSeconds: record.PurgeNotBeforeUnixSeconds,
				Phase:                     "failed",
				CreatedAtUnixSeconds:      record.CreatedAtUnixSeconds,
				UpdatedAtUnixSeconds:      record.CreatedAtUnixSeconds + 10,
				ValueReturned:             false,
			},
			ValueReturned: false,
		})
	}))
	defer statusServer.Close()
	pharos, err := newManagedPharosOperationClient(
		statusServer.URL,
		strings.Repeat("i", 32),
		statusServer.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	backend := &fakeManagedTransactionBackend{}
	bridge := &managedOperationBridge{
		transaction: backend,
		pharos:      pharos,
		store:       store,
		now:         func() time.Time { return time.Unix(1_800_000_011, 0) },
	}
	_, err = bridge.reconcile(context.Background(), managedHostReconcileRequest{
		Schema:        managedHostReconcileRequestSchema,
		SchemaVersion: 1,
		OperationRef:  record.OperationRef,
		HostRef:       record.HostRef,
		Generation:    record.Generation,
	})
	if err == nil || err.Error() != "managed_operation_removal_review_required" {
		t.Fatalf("failed removal did not stop for review: %v", err)
	}
	review, ok := store.get(record.OperationRef)
	if !ok || review.Phase != "review_required" || backend.rollbackCount != 0 {
		t.Fatalf("failed removal was restored automatically: record=%#v backend=%#v", review, backend)
	}
}
