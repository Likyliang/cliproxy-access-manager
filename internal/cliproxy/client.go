package cliproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	key     string
	http    *http.Client
}

type ExportPayload struct {
	Version    int             `json:"version"`
	ExportedAt time.Time       `json:"exported_at"`
	Usage      json.RawMessage `json:"usage"`
}

type LatestVersionResponse struct {
	LatestVersion string `json:"latest-version"`
}

func NewClient(baseURL, managementKey string, timeout time.Duration, allowInsecureTLS bool) (*Client, error) {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return nil, fmt.Errorf("base URL is required")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid base URL")
	}
	managementKey = strings.TrimSpace(managementKey)
	if managementKey == "" {
		return nil, fmt.Errorf("management key is required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if allowInsecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &Client{
		baseURL: strings.TrimRight(u.String(), "/"),
		key:     managementKey,
		http: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
	}, nil
}

func (c *Client) Health(ctx context.Context) error {
	_, err := c.doJSON(ctx, http.MethodGet, "/v0/management/config", nil)
	if err != nil {
		return fmt.Errorf("management health check failed: %w", err)
	}
	return nil
}

func (c *Client) GetAPIKeys(ctx context.Context) ([]string, error) {
	body, err := c.doJSON(ctx, http.MethodGet, "/v0/management/api-keys", nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		APIKeys []string `json:"api-keys"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode api-keys response: %w", err)
	}
	return resp.APIKeys, nil
}

func (c *Client) PutAPIKeys(ctx context.Context, keys []string) error {
	payload, err := json.Marshal(keys)
	if err != nil {
		return fmt.Errorf("marshal api keys: %w", err)
	}
	_, err = c.doJSON(ctx, http.MethodPut, "/v0/management/api-keys", payload)
	if err != nil {
		return fmt.Errorf("put api keys: %w", err)
	}
	return nil
}

func (c *Client) ExportUsage(ctx context.Context) ([]byte, time.Time, error) {
	body, err := c.doJSON(ctx, http.MethodGet, "/v0/management/usage/export", nil)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("export usage: %w", err)
	}
	var payload ExportPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, time.Time{}, fmt.Errorf("decode usage export payload: %w", err)
	}
	if payload.ExportedAt.IsZero() {
		payload.ExportedAt = time.Now().UTC()
	}
	return body, payload.ExportedAt.UTC(), nil
}

func (c *Client) ImportUsage(ctx context.Context, exportPayload []byte) error {
	if len(bytes.TrimSpace(exportPayload)) == 0 {
		return fmt.Errorf("export payload is empty")
	}
	_, err := c.doJSON(ctx, http.MethodPost, "/v0/management/usage/import", exportPayload)
	if err != nil {
		return fmt.Errorf("import usage: %w", err)
	}
	return nil
}

func (c *Client) GetLatestVersion(ctx context.Context, endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		endpoint = "/v0/management/latest-version"
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}
	body, err := c.doJSON(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	var resp LatestVersionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("decode latest-version response: %w", err)
	}
	latest := strings.TrimSpace(resp.LatestVersion)
	if latest == "" {
		return "", fmt.Errorf("missing latest version")
	}
	return latest, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, payload []byte) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("nil client")
	}
	path = strings.TrimSpace(path)
	if path == "" || !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("invalid path")
	}
	var bodyReader io.Reader
	if payload != nil {
		bodyReader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, msg)
	}
	return body, nil
}
