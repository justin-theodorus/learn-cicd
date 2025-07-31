package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_Success(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key")

	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if apiKey != "my-secret-key" {
		t.Errorf("expected API key 'my-secret-key', got '%s'", apiKey)
	}
}

func TestGetAPIKey_NoHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected error '%v', got '%v'", ErrNoAuthHeaderIncluded, err)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer my-secret-key") // wrong prefix

	_, err := GetAPIKey(headers)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected 'malformed authorization header' error, got '%v'", err)
	}
}
