package safeguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestSecretCopiesInputAndExposeReturnsCopy(t *testing.T) {
	input := []byte("super-secret")
	secret := NewSecret(input)
	input[0] = 'X'

	if got := string(secret.Expose()); got != "super-secret" {
		t.Fatalf("Expose after input mutation = %q, want %q", got, "super-secret")
	}

	exposed := secret.Expose()
	exposed[0] = 'Y'
	if got := string(secret.Expose()); got != "super-secret" {
		t.Fatalf("Expose after returned slice mutation = %q, want %q", got, "super-secret")
	}
}

func TestSecretRedaction(t *testing.T) {
	secretValue := "super-secret"
	secret := NewSecretString(secretValue)

	cases := []struct {
		name string
		got  string
	}{
		{name: "String", got: secret.String()},
		{name: "GoString", got: secret.GoString()},
		{name: "fmt percent v", got: fmt.Sprintf("%v", secret)},
		{name: "fmt percent s", got: fmt.Sprintf("%s", secret)},
		{name: "fmt percent q", got: fmt.Sprintf("%q", secret)},
		{name: "fmt percent sharp v", got: fmt.Sprintf("%#v", secret)},
		{name: "fmt percent plus v", got: fmt.Sprintf("%+v", secret)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRedactedOnly(t, tc.got, secretValue)
		})
	}

	jsonBytes, err := json.Marshal(secret)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if got, want := string(jsonBytes), "\"[REDACTED]\""; got != want {
		t.Fatalf("MarshalJSON = %q, want %q", got, want)
	}
	assertRedactedOnly(t, string(jsonBytes), secretValue)

	textBytes, err := secret.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	assertRedactedOnly(t, string(textBytes), secretValue)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("testing secret redaction", "secret", secret)
	got := buf.String()
	assertRedactedOnly(t, got, secretValue)
}

func TestSecretZeroLenEqualAndStringConstructor(t *testing.T) {
	secret := NewSecretString("token")
	if secret.IsZero() {
		t.Fatal("new secret is zero")
	}
	if got, want := secret.Len(), 5; got != want {
		t.Fatalf("Len = %d, want %d", got, want)
	}
	if !secret.Equal(NewSecret([]byte("token"))) {
		t.Fatal("Equal returned false for matching bytes")
	}
	if secret.Equal(NewSecretString("different")) {
		t.Fatal("Equal returned true for different bytes")
	}
	if got := secret.ExposeString(); got != "token" {
		t.Fatalf("ExposeString = %q, want %q", got, "token")
	}

	secret.Zero()
	if !secret.IsZero() {
		t.Fatal("Zero did not clear secret")
	}
	if got := secret.Len(); got != 0 {
		t.Fatalf("Len after Zero = %d, want 0", got)
	}
	if exposed := secret.Expose(); exposed != nil {
		t.Fatalf("Expose after Zero = %v, want nil", exposed)
	}
}

func assertRedactedOnly(t *testing.T, got, secretValue string) {
	t.Helper()
	if !strings.Contains(got, redactedText) {
		t.Fatalf("output %q does not contain %q", got, redactedText)
	}
	if strings.Contains(got, secretValue) {
		t.Fatalf("output %q leaked secret value %q", got, secretValue)
	}
}
