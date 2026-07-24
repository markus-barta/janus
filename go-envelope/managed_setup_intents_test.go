package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type managedTestFetcher struct {
	envelope managedSignedIntent
	err      error
}

func (fetcher managedTestFetcher) Fetch(context.Context, string) (managedSignedIntent, error) {
	return fetcher.envelope, fetcher.err
}

type managedTestDeclaration struct {
	err error
}

func (declaration managedTestDeclaration) Resolve(intent managedSetupIntent) (managedDeclarationContext, error) {
	bindingState := "required"
	detachProfileRef := ""
	if intent.OperationKind == "remove" {
		bindingState = "detached"
		detachProfileRef = "detach_0123456789abcdef"
	}
	return managedDeclarationContext{
		ServiceLabel:     "Canary service",
		SlotLabel:        "Admin password",
		ConsumerKind:     "managed_service",
		DeliveryKind:     "private_env_file",
		BindingState:     bindingState,
		DetachProfileRef: detachProfileRef,
		AllowedSources:   append([]string(nil), intent.AllowedSources...),
	}, declaration.err
}

func managedTestIntent(now int64) managedSetupIntent {
	return managedSetupIntent{
		Schema:                 managedSetupIntentSchema,
		SchemaVersion:          managedIntentContractVersion,
		IntentRef:              "intent_0f92b78c3d16",
		OperationKind:          "create",
		AllowedSources:         []string{"generated", "import"},
		HostRef:                "host_7f94a1c8e912",
		ServiceRef:             "svc_24b7c8f0aa19",
		SlotRef:                "slot_d5019e2a7b11",
		HumanSessionRef:        "hsn_489e126a70bf",
		IssuerRef:              managedSetupExpectedIssuerRef,
		AudienceRef:            managedSetupExpectedAudienceRef,
		NonceRef:               "nonce_a280fd61b9ce",
		DeclarationFingerprint: "decl_41268e2b772a",
		IssuedAtUnixSeconds:    now,
		ExpiresAtUnixSeconds:   now + managedIntentMaxTTLSeconds,
		ReturnTarget:           "pharos_service",
	}
}

func signManagedTestIntent(t *testing.T, seedByte byte, keyID string, intent managedSetupIntent) (managedSignedIntent, ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = seedByte
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, managedIntentSignatureMessage(keyID, payload))
	return managedSignedIntent{
		Schema:             managedSignedIntentSchema,
		SchemaVersion:      managedIntentContractVersion,
		KeyID:              keyID,
		PayloadBase64URL:   base64.RawURLEncoding.EncodeToString(payload),
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(signature),
	}, privateKey.Public().(ed25519.PublicKey)
}

func managedTestConsumer(t *testing.T, envelope managedSignedIntent, keys managedIntentKeyring, now int64) *managedSetupIntentConsumer {
	t.Helper()
	replays, err := newManagedReplayStore(filepath.Join(t.TempDir(), "replays.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &managedSetupIntentConsumer{
		fetcher:     managedTestFetcher{envelope: envelope},
		keyring:     keys,
		declaration: managedTestDeclaration{},
		replays:     replays,
		issuerRef:   managedSetupExpectedIssuerRef,
		audienceRef: managedSetupExpectedAudienceRef,
		now:         func() time.Time { return time.Unix(now, 0) },
	}
}

func TestManagedIntentConsumesOnceAndSupportsSafeKeyRotation(t *testing.T) {
	now := int64(1_784_833_200)
	intent := managedTestIntent(now)
	envelope, rotationKey := signManagedTestIntent(t, 7, "key_rotation0001", intent)
	_, oldKey := signManagedTestIntent(t, 6, "key_primary0001", intent)
	consumer := managedTestConsumer(t, envelope, managedIntentKeyring{
		"key_primary0001":  oldKey,
		"key_rotation0001": rotationKey,
	}, now+1)

	accepted, err := consumer.Consume(context.Background(), intent.IntentRef, intent.HumanSessionRef, "generated")
	if err != nil {
		t.Fatal(err)
	}
	if !validManagedRef("op_", accepted.OperationRef) ||
		accepted.Source != "generated" ||
		!reflect.DeepEqual(accepted.Intent, intent) {
		t.Fatalf("unexpected accepted intent: %#v", accepted)
	}
	_, err = consumer.Consume(context.Background(), intent.IntentRef, intent.HumanSessionRef, "generated")
	if err == nil || err.Error() != "managed_intent_replayed" {
		t.Fatalf("replay should be rejected, got %v", err)
	}
}

func TestManagedIntentInspectionIsValueFreeAndDoesNotConsumeReplayBudget(t *testing.T) {
	now := int64(1_784_833_200)
	intent := managedTestIntent(now)
	envelope, key := signManagedTestIntent(t, 7, "key_primary0001", intent)
	consumer := managedTestConsumer(
		t,
		envelope,
		managedIntentKeyring{"key_primary0001": key},
		now+1,
	)
	for attempt := 0; attempt < 2; attempt++ {
		inspected, err := consumer.Inspect(context.Background(), intent.IntentRef, intent.HumanSessionRef)
		if err != nil || !reflect.DeepEqual(inspected.Intent, intent) {
			t.Fatalf("inspection %d failed: inspected=%#v err=%v", attempt, inspected, err)
		}
	}
	accepted, err := consumer.Consume(context.Background(), intent.IntentRef, intent.HumanSessionRef, "import")
	if err != nil || !reflect.DeepEqual(accepted.Intent, intent) ||
		accepted.Source != "import" ||
		!validManagedRef("op_", accepted.OperationRef) {
		t.Fatalf("inspection consumed or changed the intent: accepted=%#v err=%v", accepted, err)
	}
	if _, err := consumer.Consume(context.Background(), intent.IntentRef, intent.HumanSessionRef, "import"); err == nil || err.Error() != "managed_intent_replayed" {
		t.Fatalf("only the committed consume should spend replay budget: %v", err)
	}
}

func TestManagedIntentRejectsSourceOutsideSignedDeclarationBeforeReplayConsume(t *testing.T) {
	now := int64(1_784_833_200)
	intent := managedTestIntent(now)
	intent.AllowedSources = []string{"generated"}
	envelope, key := signManagedTestIntent(t, 7, "key_primary0001", intent)
	consumer := managedTestConsumer(
		t,
		envelope,
		managedIntentKeyring{"key_primary0001": key},
		now+1,
	)
	consumer.declaration = managedTestDeclaration{}

	if _, err := consumer.Consume(context.Background(), intent.IntentRef, intent.HumanSessionRef, "import"); err == nil || err.Error() != "managed_intent_source_denied" {
		t.Fatalf("unsigned source choice should be denied, got %v", err)
	}
	accepted, err := consumer.Consume(context.Background(), intent.IntentRef, intent.HumanSessionRef, "generated")
	if err != nil || accepted.Source != "generated" {
		t.Fatalf("source denial should not consume replay budget: accepted=%#v err=%v", accepted, err)
	}
}

func TestManagedIntentRejectsIdentityTimeAudienceDriftAndTampering(t *testing.T) {
	now := int64(1_784_833_200)
	tests := []struct {
		name          string
		mutate        func(*managedSetupIntent)
		requestRef    string
		humanRef      string
		consumerNow   int64
		declaration   error
		tamperPayload bool
		want          string
	}{
		{
			name:        "wrong user",
			humanRef:    "hsn_someone_else0",
			consumerNow: now + 1,
			want:        "managed_intent_wrong_user",
		},
		{
			name: "wrong audience",
			mutate: func(intent *managedSetupIntent) {
				intent.AudienceRef = "sys_another_audience0"
			},
			consumerNow: now + 1,
			want:        "managed_intent_wrong_audience",
		},
		{
			name: "wrong issuer",
			mutate: func(intent *managedSetupIntent) {
				intent.IssuerRef = "sys_another_issuer000"
			},
			consumerNow: now + 1,
			want:        "managed_intent_wrong_issuer",
		},
		{
			name:        "expired without extending expiry by skew",
			consumerNow: now + managedIntentMaxTTLSeconds,
			want:        "managed_intent_expired",
		},
		{
			name: "too far in future",
			mutate: func(intent *managedSetupIntent) {
				intent.IssuedAtUnixSeconds = now + managedIntentClockSkewSeconds + 1
				intent.ExpiresAtUnixSeconds = intent.IssuedAtUnixSeconds + 60
			},
			consumerNow: now,
			want:        "managed_intent_not_yet_valid",
		},
		{
			name:        "declaration drift",
			consumerNow: now + 1,
			declaration: managedIntentError("managed_intent_declaration_drift"),
			want:        "managed_intent_declaration_drift",
		},
		{
			name:        "reference mismatch",
			requestRef:  "intent_different0001",
			consumerNow: now + 1,
			want:        "managed_intent_reference_mismatch",
		},
		{
			name:          "signed payload tampering",
			consumerNow:   now + 1,
			tamperPayload: true,
			want:          "managed_intent_signature_invalid",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			intent := managedTestIntent(now)
			if test.mutate != nil {
				test.mutate(&intent)
			}
			envelope, key := signManagedTestIntent(t, 9, "key_primary0001", intent)
			if test.tamperPayload {
				payload, err := base64.RawURLEncoding.DecodeString(envelope.PayloadBase64URL)
				if err != nil {
					t.Fatal(err)
				}
				payload[len(payload)/2] ^= 1
				envelope.PayloadBase64URL = base64.RawURLEncoding.EncodeToString(payload)
			}
			consumer := managedTestConsumer(
				t,
				envelope,
				managedIntentKeyring{"key_primary0001": key},
				test.consumerNow,
			)
			consumer.declaration = managedTestDeclaration{err: test.declaration}
			requestRef := test.requestRef
			if requestRef == "" {
				requestRef = intent.IntentRef
			}
			humanRef := test.humanRef
			if humanRef == "" {
				humanRef = intent.HumanSessionRef
			}
			_, err := consumer.Consume(context.Background(), requestRef, humanRef, "generated")
			if err == nil || err.Error() != test.want {
				t.Fatalf("got %v, want %s", err, test.want)
			}
			if strings.Contains(err.Error(), intent.IntentRef) || strings.Contains(err.Error(), intent.HumanSessionRef) {
				t.Fatalf("denial leaked a reference: %v", err)
			}
		})
	}
}

func TestManagedIntentRejectsControlPlaneVersionAndUnknownKey(t *testing.T) {
	now := int64(1_784_833_200)
	intent := managedTestIntent(now)
	envelope, key := signManagedTestIntent(t, 10, "key_primary0001", intent)

	versionSkew := envelope
	versionSkew.SchemaVersion = 2
	if _, err := verifyManagedSetupIntent(versionSkew, managedIntentKeyring{"key_primary0001": key}); err == nil || err.Error() != "managed_intent_version_unsupported" {
		t.Fatalf("version skew should be rejected, got %v", err)
	}
	if _, err := verifyManagedSetupIntent(envelope, managedIntentKeyring{}); err == nil || err.Error() != "managed_intent_signing_key_unknown" {
		t.Fatalf("unknown key should be rejected, got %v", err)
	}
}

func TestManagedIntentCrossLanguageFixtureValues(t *testing.T) {
	envelope, publicKey := signManagedTestIntent(
		t,
		9,
		"key_rotating0001",
		managedTestIntent(1_784_833_200),
	)
	if got := base64.RawURLEncoding.EncodeToString(publicKey); got != "_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg" {
		t.Fatalf("public key drifted: %s", got)
	}
	if envelope.PayloadBase64URL != "eyJzY2hlbWEiOiJpbnNwci5qYW51cy5tYW5hZ2VkLXNlcnZpY2Utc2V0dXAtaW50ZW50LnYxIiwic2NoZW1hX3ZlcnNpb24iOjEsImludGVudF9yZWYiOiJpbnRlbnRfMGY5MmI3OGMzZDE2Iiwib3BlcmF0aW9uX2tpbmQiOiJjcmVhdGUiLCJhbGxvd2VkX3NvdXJjZXMiOlsiZ2VuZXJhdGVkIiwiaW1wb3J0Il0sImhvc3RfcmVmIjoiaG9zdF83Zjk0YTFjOGU5MTIiLCJzZXJ2aWNlX3JlZiI6InN2Y18yNGI3YzhmMGFhMTkiLCJzbG90X3JlZiI6InNsb3RfZDUwMTllMmE3YjExIiwiaHVtYW5fc2Vzc2lvbl9yZWYiOiJoc25fNDg5ZTEyNmE3MGJmIiwiaXNzdWVyX3JlZiI6InN5c19waGFyb3NfY29udHJvbF9wbGFuZV92MSIsImF1ZGllbmNlX3JlZiI6InN5c19qYW51c19zZWNyZXRfY3VzdG9keV92MSIsIm5vbmNlX3JlZiI6Im5vbmNlX2EyODBmZDYxYjljZSIsImRlY2xhcmF0aW9uX2ZpbmdlcnByaW50IjoiZGVjbF80MTI2OGUyYjc3MmEiLCJpc3N1ZWRfYXRfdW5peF9zZWNzIjoxNzg0ODMzMjAwLCJleHBpcmVzX2F0X3VuaXhfc2VjcyI6MTc4NDgzMzUwMCwicmV0dXJuX3RhcmdldCI6InBoYXJvc19zZXJ2aWNlIn0" {
		t.Fatalf("cross-language payload serialization drifted: %s", envelope.PayloadBase64URL)
	}
	if envelope.SignatureBase64URL != "3ThLNIbJ9GUo-deWwOxn8na6tuFhNwPaMo7QY4M1g4CE81TFYBzv8lBbHjCSkqKq2pRJhcUkaogKMye59SxcBg" {
		t.Fatalf("cross-language signature drifted: %s", envelope.SignatureBase64URL)
	}
}

func TestManagedHTTPIntentFetcherAuthenticatesAndHandlesCancellationOutage(t *testing.T) {
	now := int64(1_784_833_200)
	envelope, _ := signManagedTestIntent(t, 11, "key_primary0001", managedTestIntent(now))
	token := strings.Repeat("t", 32)
	cancelled := false
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.RawQuery != "" ||
			request.URL.Path != "/internal/managed-service-setup-intents/intent_0f92b78c3d16" ||
			request.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("unsafe or unauthenticated request: %s %#v", request.URL.String(), request.Header)
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		if cancelled {
			response.WriteHeader(http.StatusGone)
			_ = json.NewEncoder(response).Encode(map[string]any{
				"schema":         managedIntentDenialSchema,
				"schema_version": 1,
				"outcome":        "denied",
				"reason_code":    "managed_intent_cancelled",
				"value_returned": false,
			})
			return
		}
		_ = json.NewEncoder(response).Encode(envelope)
	}))
	fetcher, err := newManagedHTTPIntentFetcher(server.URL, token, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetcher.Fetch(context.Background(), "intent_0f92b78c3d16"); err != nil {
		t.Fatal(err)
	}
	cancelled = true
	if _, err := fetcher.Fetch(context.Background(), "intent_0f92b78c3d16"); err == nil || err.Error() != "managed_intent_cancelled" {
		t.Fatalf("cancelled intent should stay cancelled, got %v", err)
	}
	server.Close()
	if _, err := fetcher.Fetch(context.Background(), "intent_0f92b78c3d16"); err == nil || err.Error() != "managed_intent_pharos_unavailable" {
		t.Fatalf("outage should be stable and value-free, got %v", err)
	}
}

func TestManagedReturnURLIsFixedOriginAndCannotBecomeCallback(t *testing.T) {
	got, err := managedReturnURL("https://pharos.example.test", "op_d43a770e9bc2")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://pharos.example.test/managed-service/operations/op_d43a770e9bc2" {
		t.Fatalf("unexpected return URL: %s", got)
	}
	for _, shaped := range []string{
		"https://pharos.example.test/path",
		"https://user@pharos.example.test",
		"https://pharos.example.test?callback=https://evil.test",
		"http://pharos.example.test",
	} {
		if _, err := managedReturnURL(shaped, "op_d43a770e9bc2"); err == nil {
			t.Fatalf("accepted caller-shaped return origin %q", shaped)
		}
	}
}

func TestManagedManifestResolverRecomputesFingerprintAndFailsClosed(t *testing.T) {
	manifest := managedManifest{
		Schema:        managedManifestSchema,
		SchemaVersion: 1,
		GeneratedBy:   "nixcfg",
		HostRef:       "host_7f94a1c8e912",
		Services: []managedManifestService{{
			ServiceRef:  "svc_24b7c8f0aa19",
			SafeLabel:   "<Canary & service>",
			RuntimeKind: "compose",
			Slots: []managedManifestSlot{{
				SlotRef:      "slot_d5019e2a7b11",
				SafeLabel:    "Admin <password> & token",
				ConsumerKind: "managed_service",
				Delivery: managedManifestDelivery{
					Kind:       "private_env_file",
					ProfileRef: "delivery_2ed71ad75c98",
				},
				Reload: managedManifestReload{
					Method:     "compose_recreate",
					ProfileRef: "reload_5e776ec5d9a1",
				},
				Health: managedManifestHealth{
					Probe:      "compose_healthcheck",
					ProfileRef: "health_84c12f390b2a",
				},
				AllowedSources: []string{"generated", "import"},
			}},
		}},
	}
	canonical := managedCanonicalManifest{
		HostRef: manifest.HostRef,
		Services: []managedCanonicalManifestService{{
			RuntimeKind: manifest.Services[0].RuntimeKind,
			SafeLabel:   manifest.Services[0].SafeLabel,
			ServiceRef:  manifest.Services[0].ServiceRef,
			Slots: []managedCanonicalManifestSlot{{
				AllowedSources: manifest.Services[0].Slots[0].AllowedSources,
				ConsumerKind:   manifest.Services[0].Slots[0].ConsumerKind,
				Delivery:       manifest.Services[0].Slots[0].Delivery,
				Health:         manifest.Services[0].Slots[0].Health,
				Reload:         manifest.Services[0].Slots[0].Reload,
				SafeLabel:      manifest.Services[0].Slots[0].SafeLabel,
				SlotRef:        manifest.Services[0].Slots[0].SlotRef,
			}},
		}},
	}
	rawCanonical, err := encodeManagedCanonicalJSON(canonical)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(rawCanonical)
	manifest.DeclarationFingerprint = "decl_" + hex.EncodeToString(fingerprint[:])
	if manifest.DeclarationFingerprint != "decl_eed42d4f2d389904ad63beb09256db37f38c3435c15b46840faae1ac181b70e4" {
		t.Fatalf("Nix/Rust/Go canonical fingerprint drifted: %s", manifest.DeclarationFingerprint)
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	intent := managedTestIntent(1_784_833_200)
	intent.DeclarationFingerprint = manifest.DeclarationFingerprint
	resolver := managedManifestResolver{paths: []string{path}}
	if _, err := resolver.Resolve(intent); err != nil {
		t.Fatal(err)
	}

	manifest.Services[0].SafeLabel = "tampered"
	tampered, _ := json.Marshal(manifest)
	if err := os.WriteFile(path, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(intent); err == nil || err.Error() != "managed_intent_declaration_unavailable" {
		t.Fatalf("fingerprint drift must fail closed, got %v", err)
	}
}

func TestManagedV2DetachRequiresNoCreationSources(t *testing.T) {
	slot := managedManifestSlot{
		BindingState: "detached",
		Detach: managedManifestDetach{
			Method:     "compose_stop_and_verify",
			ProfileRef: "detach_8a0f4e271c93",
		},
	}
	if !validManagedDetachPolicy(managedManifestCurrentVersion, slot) ||
		!validManagedSlotSourcePolicy(managedManifestCurrentVersion, slot) {
		t.Fatal("reviewed detached slot with no creation sources was rejected")
	}
	slot.AllowedSources = []string{"generated"}
	if validManagedSlotSourcePolicy(managedManifestCurrentVersion, slot) {
		t.Fatal("detached slot retained a creation source")
	}
	slot.BindingState = "required"
	if !validManagedSlotSourcePolicy(managedManifestCurrentVersion, slot) {
		t.Fatal("required slot lost its explicit creation source")
	}
	slot.AllowedSources = nil
	if validManagedSlotSourcePolicy(managedManifestCurrentVersion, slot) {
		t.Fatal("required slot admitted an empty creation policy")
	}
}

func TestManagedHumanSessionBindingIsStableAndIssuerScoped(t *testing.T) {
	first := managedHumanSessionRef("https://issuer.example.test", "subject-1")
	if first != "hsn_9faf4f59563351db0902dcb553e34717e3d37497b11422efcbd54d9b367c415a" {
		t.Fatalf("cross-language human binding drifted: %s", first)
	}
	if !validManagedRef("hsn_", first) {
		t.Fatalf("invalid session ref %q", first)
	}
	if first != managedHumanSessionRef("https://issuer.example.test", "subject-1") {
		t.Fatal("session binding is not deterministic")
	}
	if first != managedHumanSessionRef("https://issuer.example.test/", "subject-1") {
		t.Fatal("cosmetic issuer slash changed the session binding")
	}
	if first == managedHumanSessionRef("https://issuer.example.test", "subject-2") ||
		first == managedHumanSessionRef("https://other-issuer.example.test", "subject-1") {
		t.Fatal("session binding is not principal and issuer scoped")
	}
}

func TestManagedSetupRuntimeConfigIsAllOrNothingAndLoadsRotatingKeys(t *testing.T) {
	for _, name := range []string{
		"JANUS_MANAGED_SETUP_PHAROS_ORIGIN",
		"JANUS_MANAGED_SETUP_PHAROS_RETURN_ORIGIN",
		"JANUS_MANAGED_SETUP_INTERNAL_TOKEN_FILE",
		"JANUS_MANAGED_SETUP_VERIFICATION_KEYS_FILE",
		"JANUS_MANAGED_SETUP_MANIFEST_PATHS",
		"JANUS_MANAGED_WEB_TRANSACTION_SOCKET",
		"JANUS_MANAGED_HOST_TOKEN_GENERATION_DIR",
		"JANUS_MANAGED_HOST_ENVELOPE_OUTBOX_DIR",
	} {
		t.Setenv(name, "")
	}
	if config, err := loadManagedSetupRuntimeConfigFromEnv(); err != nil || config != nil {
		t.Fatalf("disabled config should be empty: %#v %v", config, err)
	}
	t.Setenv("JANUS_MANAGED_SETUP_PHAROS_ORIGIN", "https://pharos.example.test")
	if _, err := loadManagedSetupRuntimeConfigFromEnv(); err == nil {
		t.Fatal("partial config should fail")
	}

	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("t", 32)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, publicKey := signManagedTestIntent(
		t,
		9,
		"key_rotating0001",
		managedTestIntent(1_784_833_200),
	)
	keysPath := filepath.Join(directory, "keys.json")
	keys := managedVerificationKeyDocument{
		Schema:        managedVerificationKeysSchema,
		SchemaVersion: 1,
		Keys: []managedVerificationKey{{
			KeyID:              "key_rotating0001",
			PublicKeyBase64URL: base64.RawURLEncoding.EncodeToString(publicKey),
		}},
	}
	rawKeys, _ := json.Marshal(keys)
	if err := os.WriteFile(keysPath, rawKeys, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JANUS_MANAGED_SETUP_INTERNAL_TOKEN_FILE", tokenPath)
	t.Setenv("JANUS_MANAGED_SETUP_VERIFICATION_KEYS_FILE", keysPath)
	t.Setenv("JANUS_MANAGED_SETUP_MANIFEST_PATHS", "/managed/one.json,/managed/two.json")
	t.Setenv("JANUS_MANAGED_WEB_TRANSACTION_SOCKET", "/run/janus/managed-transaction.sock")
	tokenGenerationDirectory := filepath.Join(directory, "host-token-generations")
	envelopeOutboxDirectory := filepath.Join(directory, "host-envelope-outbox")
	if err := os.Mkdir(tokenGenerationDirectory, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(envelopeOutboxDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JANUS_MANAGED_HOST_TOKEN_GENERATION_DIR", tokenGenerationDirectory)
	t.Setenv("JANUS_MANAGED_HOST_ENVELOPE_OUTBOX_DIR", envelopeOutboxDirectory)
	config, err := loadManagedSetupRuntimeConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if config.PharosReturnOrigin != "https://pharos.example.test" ||
		len(config.Keyring) != 1 ||
		len(config.ManifestPaths) != 2 ||
		config.TransactionSocket != "/run/janus/managed-transaction.sock" ||
		config.HostTokenGenerationDir != tokenGenerationDirectory ||
		config.HostEnvelopeOutboxDir != envelopeOutboxDirectory {
		t.Fatalf("unexpected runtime config: %#v", config)
	}
	if err := os.Chmod(tokenPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadManagedSetupRuntimeConfigFromEnv(); err == nil {
		t.Fatal("group/world-readable internal token should fail closed")
	}
}

func TestManagedReplayStateSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replays.json")
	store, err := newManagedReplayStore(path)
	if err != nil {
		t.Fatal(err)
	}
	intent := managedTestIntent(1_784_833_200)
	if _, err := store.consume(intent, 1_784_833_201); err != nil {
		t.Fatal(err)
	}
	restarted, err := newManagedReplayStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.consume(intent, 1_784_833_202); err == nil || err.Error() != "managed_intent_replayed" {
		t.Fatalf("replay state did not survive restart: %v", err)
	}
}

func TestManagedHTTPFetcherRejectsRedirectAndUntrustedDenialShape(t *testing.T) {
	token := strings.Repeat("z", 32)
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"schema":"evil","reason_code":"managed_intent_cancelled"}`))
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		http.Redirect(response, &http.Request{}, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	fetcher, err := newManagedHTTPIntentFetcher(redirect.URL, token, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = fetcher.Fetch(context.Background(), "intent_0f92b78c3d16")
	if err == nil || !errors.Is(err, managedIntentError("managed_intent_pharos_unavailable")) {
		t.Fatalf("redirect should fail closed, got %v", err)
	}
}
