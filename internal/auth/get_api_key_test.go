package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	type test struct {
		name    string
		headers http.Header
		want    string
		wantErr error
	}
	tests := []test{
		{
			name:    "valid API key",
			headers: http.Header{"Authorization": []string{"ApiKey 12345"}},
			want:    "12345",
			wantErr: nil,
		},
		{
			name:    "no auth header",
			headers: http.Header{},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "malformed auth header",
			headers: http.Header{"Authorization": []string{"InvalidHeader"}},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "wrong autho type",
			headers: http.Header{"Authorization": []string{"Bearer 12345"}},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "extra spaces in auth header",
			headers: http.Header{"Authorization": []string{"ApiKey	12345"}},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "miltiple auth headers",
			headers: http.Header{"Authorization": []string{"ApiKey 12345", "ApiKey 67890"}},
			want:    "12345",
			wantErr: nil,
		},
		{
			name:    "auth header with extra spaces",
			headers: http.Header{"Authorization": []string{"  ApiKey 12345  "}},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "auth header with only ApiKey",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(c *testing.T) {
			got, err := GetAPIKey(tc.headers)
			if got != tc.want {
				c.Errorf("expected apiKey to be '%s', got: '%s'", tc.want, got)
			}
			if (err == nil) != (tc.wantErr == nil) || (err != nil && err.Error() != tc.wantErr.Error()) {
				c.Errorf("expected error: %v, got: %v", tc.wantErr, err)
			}
		})
	}
}
