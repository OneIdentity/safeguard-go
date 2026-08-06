package safeguard

import (
	"strings"
	"testing"
)

func TestServiceBaseURL(t *testing.T) {
	cases := []struct {
		name       string
		service    Service
		host       string
		apiVersion string
		want       string
	}{
		{name: "core", service: Core, host: "HOST", want: "https://HOST/service/core/v4/"},
		{name: "appliance", service: Appliance, host: "HOST", want: "https://HOST/service/appliance/v4/"},
		{name: "notification", service: Notification, host: "HOST", want: "https://HOST/service/notification/v4/"},
		{name: "a2a", service: A2A, host: "HOST", want: "https://HOST/service/a2a/v4/"},
		{name: "event", service: Event, host: "HOST", want: "https://HOST/service/event/v4/"},
		{name: "management", service: Management, host: "HOST", want: "https://HOST/service/management/v4/"},
		{name: "rsts", service: RSTS, host: "HOST", want: "https://HOST/RSTS/"},
		{name: "api version override", service: Core, host: "HOST", apiVersion: "v3", want: "https://HOST/service/core/v3/"},
		{name: "empty api version default", service: Core, host: "HOST", apiVersion: "", want: "https://HOST/service/core/v4/"},
		{name: "host with scheme", service: Core, host: "https://h", want: "https://h/service/core/v4/"},
		{name: "host without scheme", service: Core, host: "h", want: "https://h/service/core/v4/"},
		{name: "host trailing slash", service: Core, host: "https://h/", want: "https://h/service/core/v4/"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.service.baseURL(tc.host, tc.apiVersion)
			if err != nil {
				t.Fatalf("baseURL: %v", err)
			}
			if got != tc.want {
				t.Fatalf("baseURL = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestServiceBaseURLErrors(t *testing.T) {
	cases := []struct {
		name    string
		service Service
		host    string
	}{
		{name: "empty host", service: Core, host: ""},
		{name: "unknown service", service: Service("unknown"), host: "HOST"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.service.baseURL(tc.host, DefaultAPIVersion)
			if err == nil {
				t.Fatal("baseURL error = nil, want error")
			}
			if tc.name == "unknown service" && !strings.Contains(err.Error(), "unknown service") {
				t.Fatalf("error = %q, want unknown service", err)
			}
		})
	}
}
