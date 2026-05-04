package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Nominal/valid case: correct ApiKey header
	apiKey, err := GetAPIKey(http.Header{"Authorization": []string{"ApiKey 12345"}})
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if apiKey != "12345" {
		t.Errorf("expected apiKey to be '12345', got: %v", apiKey)
	}

	// no auth header included
	_, err = GetAPIKey(http.Header{})
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Errorf("expected error: %v, got: %v", ErrNoAuthHeaderIncluded, err)
	}

	// malformed auth header
	_, err = GetAPIKey(http.Header{"Authorization": []string{"InvalidHeader"}})
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected error: %v, got: %v", "malformed authorization header", err)
	}

	// wrong auth type
	_, err = GetAPIKey(http.Header{"Authorization": []string{"Bearer 12345"}})
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected error: %v, got: %v", "malformed authorization header", err)
	}

	// extra spaces in auth header
	_, err = GetAPIKey(http.Header{"Authorization": []string{"ApiKey	12345"}})
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected error: %v, got: %v", "malformed authorization header", err)
	}

	// multiple auth headers (should take the first one)
	_, err = GetAPIKey(http.Header{"Authorization": []string{"ApiKey 12345", "ApiKey 67890"}})
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

	// auth header with extra spaces
	_, err = GetAPIKey(http.Header{"Authorization": []string{"  ApiKey 12345  "}})
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected error: %v, got: %v", "malformed authorization header", err)
	}

	// auth header with only "ApiKey"
	_, err = GetAPIKey(http.Header{"Authorization": []string{"ApiKey"}})
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected error: %v, got: %v", "malformed authorization header", err)
	}
}
