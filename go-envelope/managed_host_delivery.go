package main

import (
	"io"
	"mime"
	"net/http"
	"strings"
)

const managedHostReconcileMaxBytes = int64(1024)

func (app *App) handleManagedHostEnvelope(w http.ResponseWriter, r *http.Request) {
	managedSecretResponseBoundary(w)
	if app.managedBridge == nil || r.URL.RawQuery != "" {
		app.renderSafeFailure(w, r, http.StatusNotFound, "managed_host_envelope_denied", "Managed host delivery is unavailable.", nil)
		return
	}
	hostRef := r.PathValue("hostRef")
	operationRef := r.PathValue("operationRef")
	token, ok := exactBearerToken(r)
	if !ok || !validManagedRef("host_", hostRef) || !validManagedRef("op_", operationRef) ||
		!app.managedBridge.hostAuthorized(hostRef, token) {
		app.renderSafeFailure(w, r, http.StatusUnauthorized, "managed_host_envelope_denied", "Managed host delivery was denied.", nil)
		return
	}
	packet, err := app.managedBridge.packetForHost(operationRef, hostRef)
	if err != nil {
		app.renderSafeFailure(w, r, http.StatusNotFound, "managed_host_envelope_unavailable", "The managed envelope is unavailable.", nil)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(packet)
}

func (app *App) handleManagedHostReconcile(w http.ResponseWriter, r *http.Request) {
	managedSecretResponseBoundary(w)
	if app.managedBridge == nil || r.URL.RawQuery != "" ||
		r.Body == nil || len(r.TransferEncoding) != 0 ||
		r.ContentLength <= 0 || r.ContentLength > managedHostReconcileMaxBytes {
		app.renderSafeFailure(w, r, http.StatusBadRequest, "managed_reconcile_request_invalid", "The managed operation update was invalid.", nil)
		return
	}
	mediaType, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(parameters) != 0 {
		app.renderSafeFailure(w, r, http.StatusBadRequest, "managed_reconcile_request_invalid", "The managed operation update was invalid.", nil)
		return
	}
	operationRef := r.PathValue("operationRef")
	raw, err := io.ReadAll(io.LimitReader(r.Body, managedHostReconcileMaxBytes+1))
	if err != nil || int64(len(raw)) > managedHostReconcileMaxBytes || !requestBodyAtEOF(r.Body) {
		app.renderSafeFailure(w, r, http.StatusBadRequest, "managed_reconcile_request_invalid", "The managed operation update was invalid.", nil)
		return
	}
	var request managedHostReconcileRequest
	token, ok := exactBearerToken(r)
	if decodeStrictJSON(raw, &request) != nil ||
		request.Schema != managedHostReconcileRequestSchema ||
		request.SchemaVersion != 1 ||
		request.OperationRef != operationRef ||
		!validManagedRef("op_", request.OperationRef) ||
		!validManagedRef("host_", request.HostRef) ||
		request.Generation == 0 ||
		!ok ||
		!app.managedBridge.hostAuthorized(request.HostRef, token) {
		app.renderSafeFailure(w, r, http.StatusUnauthorized, "managed_reconcile_request_denied", "The managed operation update was denied.", nil)
		return
	}
	if _, err := app.managedBridge.reconcile(r.Context(), request); err != nil {
		status := http.StatusServiceUnavailable
		if err.Error() == "managed_operation_not_terminal" {
			status = http.StatusConflict
		}
		app.renderSafeFailure(w, r, status, "managed_reconcile_incomplete", "The managed operation is not ready to reconcile.", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func exactBearerToken(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	token, ok := strings.CutPrefix(values[0], "Bearer ")
	return token, ok && len(token) >= 32 && !strings.ContainsAny(token, " \t\r\n")
}

func managedHostEnvelopePath(path string) bool {
	rest, ok := strings.CutPrefix(path, "/internal/managed-service-host-envelopes/")
	if !ok {
		return false
	}
	parts := strings.Split(rest, "/")
	return len(parts) == 2 &&
		validManagedRef("host_", parts[0]) &&
		validManagedRef("op_", parts[1])
}

func managedHostReconcilePath(path string) bool {
	rest, ok := strings.CutPrefix(path, "/internal/managed-service-operations/")
	if !ok {
		return false
	}
	operationRef, ok := strings.CutSuffix(rest, "/reconcile")
	return ok && !strings.Contains(operationRef, "/") &&
		validManagedRef("op_", operationRef)
}
