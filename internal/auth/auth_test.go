package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "no auth header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header",
			headers: http.Header{
				"Authorization": []string{"Bearer something"},
			},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey mysecretkey123"},
			},
			wantKey: "mysecretkey123",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Errorf("expected key %q, got %q", tt.wantKey, gotKey)
			}
			if (err != nil && tt.wantErr == nil) || (err == nil && tt.wantErr != nil) {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			} else if err != nil && tt.wantErr != nil && err.Error() != tt.wantErr.Error() {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}
