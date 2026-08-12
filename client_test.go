package safeguard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
)

func TestNewClientErrors(t *testing.T) {
	_, err := newClient("")
	if !errors.Is(err, errEmptyHost) {
		t.Fatalf("newClient empty host error = %v, want errEmptyHost", err)
	}

	_, err = newClient("example.test", WithAPIVersion(""))
	if !errors.Is(err, errEmptyAPIVersion) {
		t.Fatalf("newClient bad option error = %v, want errEmptyAPIVersion", err)
	}
}

func TestCloseZeroesTokenAndPreventsUse(t *testing.T) {
	client, err := newClient("example.test")
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	client.setUserToken(NewSecretString("token"), false)
	state := client.token.Load()

	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	for _, b := range state.token.Expose() {
		if b != 0 {
			t.Fatalf("token byte after Close = %d, want 0", b)
		}
	}

	_, err = client.Invoke(context.Background(), MethodGet, Notification, "Status", nil)
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("Invoke after Close error = %v, want ErrClosed", err)
	}
	_, err = client.Get(context.Background(), Notification, "Status")
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("Get after Close error = %v, want ErrClosed", err)
	}
	_, err = client.TokenLifetimeRemaining(context.Background())
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("TokenLifetimeRemaining after Close error = %v, want ErrClosed", err)
	}
}

func TestLogoutClearsSession(t *testing.T) {
	client, err := newClient("example.test")
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	defer closeClient(t, client)

	client.setUserToken(NewSecretString("token"), false)
	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if got := client.currentAuthorization().headerValue(); got != "" {
		t.Fatalf("currentAuthorization after Logout = %q, want empty", got)
	}
	state := client.token.Load()
	if state == nil || !state.anonymous || state.epoch != 0 {
		t.Fatalf("token state after Logout = %+v, want anonymous epoch 0", state)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := client.Logout(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Logout after Close error = %v, want ErrClosed", err)
	}
}

func TestSetUserTokenGenerationAndAuthorization(t *testing.T) {
	client, err := newClient("example.test")
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	defer closeClient(t, client)

	if got := client.currentAuthorization().headerValue(); got != "" {
		t.Fatalf("initial currentAuthorization = %q, want empty", got)
	}
	before := client.token.Load()
	client.setUserToken(NewSecretString("one"), false)
	afterOne := client.token.Load()
	client.setUserToken(NewSecretString("two"), false)
	afterTwo := client.token.Load()

	if afterOne.epoch != before.epoch || afterTwo.epoch != before.epoch {
		t.Fatalf("epoch changed from %d to %d/%d", before.epoch, afterOne.epoch, afterTwo.epoch)
	}
	if got, want := afterOne.generation, before.generation+1; got != want {
		t.Fatalf("first generation = %d, want %d", got, want)
	}
	if got, want := afterTwo.generation, afterOne.generation+1; got != want {
		t.Fatalf("second generation = %d, want %d", got, want)
	}
	if got, want := client.currentAuthorization().headerValue(), "Bearer two"; got != want {
		t.Fatalf("currentAuthorization = %q, want %q", got, want)
	}
}

func TestTokenLifetimeRemaining(t *testing.T) {
	client, err := newClient("example.test")
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	defer closeClient(t, client)

	_, err = client.TokenLifetimeRemaining(context.Background())
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("anonymous TokenLifetimeRemaining error = %v, want ErrNotAuthenticated", err)
	}
}

func TestRefreshToken(t *testing.T) {
	client, err := newClient("example.test")
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	defer closeClient(t, client)

	err = client.RefreshToken(context.Background())
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("anonymous RefreshToken error = %v, want ErrNotAuthenticated", err)
	}

	client.setUserToken(NewSecretString("token"), false)
	err = client.RefreshToken(context.Background())
	if !errors.Is(err, ErrNotRefreshable) {
		t.Fatalf("token RefreshToken error = %v, want ErrNotRefreshable", err)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err = client.RefreshToken(context.Background())
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("closed RefreshToken error = %v, want ErrClosed", err)
	}
}

func TestConcurrentGetAndSetUserTokenRace(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"ok":true}`))
		if err != nil {
			t.Errorf("Write: %v", err)
		}
	}))
	defer server.Close()
	defer closeClient(t, client)

	const workers = 8
	const iterations = 50
	var wg sync.WaitGroup
	errCh := make(chan error, workers*iterations)

	wg.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				full, err := client.Get(context.Background(), Notification, "Status")
				if err != nil {
					errCh <- err
					return
				}
				if full.StatusCode != http.StatusOK {
					errCh <- fmt.Errorf("status = %d, want %d", full.StatusCode, http.StatusOK)
					return
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < workers*iterations; i++ {
			client.setUserToken(NewSecretString(fmt.Sprintf("token-%d", i)), false)
		}
	}()

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}
