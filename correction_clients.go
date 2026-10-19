package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"route-monitor/internal/routebridge"
)

type correctionError struct{ Code string }

func (e correctionError) Error() string { return e.Code }
func errorCode(e error, fallback string) string {
	var c correctionError
	if errors.As(e, &c) {
		return c.Code
	}
	return fallback
}

type sshBridge struct{ cfg CorrectionConfig }

func (b sshBridge) Call(ctx context.Context, r routebridge.Request) (routebridge.Response, error) {
	data, e := json.Marshal(r)
	if e != nil {
		return routebridge.Response{}, correctionError{"bridge_request_invalid"}
	}
	ctx, cancel := context.WithTimeout(ctx, 80*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/ssh", "-F", b.cfg.SSHConfig, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", b.cfg.SSHHost, b.cfg.BridgePath)
	cmd.Stdin = bytes.NewReader(data)
	var output limitedBuffer
	output.limit = 8 << 20
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	err := cmd.Run()
	var result routebridge.Response
	if json.Unmarshal(output.Bytes(), &result) != nil {
		return result, correctionError{"bridge_unavailable"}
	}
	if err != nil || !result.OK {
		code := result.Code
		if code == "" {
			code = "bridge_unavailable"
		}
		return result, correctionError{code}
	}
	return result, nil
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("response_too_large")
	}
	return b.Buffer.Write(p)
}

type cloudRules struct {
	cfg    CorrectionConfig
	client *http.Client
}

func newCloudRules(cfg CorrectionConfig) *cloudRules {
	tr := &http.Transport{Proxy: nil}
	if cfg.HTTPProxy != "" {
		u, _ := url.Parse(cfg.HTTPProxy)
		tr.Proxy = http.ProxyURL(u)
	}
	return &cloudRules{cfg: cfg, client: &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (c *cloudRules) call(ctx context.Context, action string, body, out any) error {
	stat, e := os.Stat(c.cfg.TokenFile)
	if e != nil || stat.Mode().Perm()&0077 != 0 {
		return correctionError{"rules_token_unavailable"}
	}
	token, e := os.ReadFile(c.cfg.TokenFile)
	if e != nil || len(token) > 256 {
		return correctionError{"rules_token_unavailable"}
	}
	var input io.Reader
	method := http.MethodGet
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return correctionError{"cloud_request_invalid"}
		}
		input = bytes.NewReader(b)
		method = http.MethodPost
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.cfg.RulesURL, "/")+"/api/configs/"+c.cfg.Profile+"/"+action, input)
	if e != nil {
		return correctionError{"cloud_request_invalid"}
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 RouteMonitor/"+version)
	r, e := c.client.Do(req)
	if e != nil {
		return correctionError{"cloud_unavailable"}
	}
	defer r.Body.Close()
	if r.StatusCode == 409 {
		return correctionError{"cloud_conflict"}
	}
	if r.StatusCode == 401 || r.StatusCode == 403 {
		return correctionError{"cloud_unauthorized"}
	}
	if r.StatusCode != 200 {
		return correctionError{"cloud_unavailable"}
	}
	if json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(out) != nil {
		return correctionError{"cloud_invalid_response"}
	}
	return nil
}
func (c *cloudRules) State(ctx context.Context) (RuleState, error) {
	var v RuleState
	e := c.call(ctx, "automatic-state", nil, &v)
	return v, e
}
func (c *cloudRules) Check(ctx context.Context, r RuleRequest) (RulePreview, error) {
	var v RulePreview
	e := c.call(ctx, "automatic-check", r, &v)
	return v, e
}
func (c *cloudRules) Publish(ctx context.Context, r RuleRequest) (RuleReceipt, error) {
	var v RuleReceipt
	e := c.call(ctx, "automatic-publish", r, &v)
	return v, e
}
func (c *cloudRules) Receipt(ctx context.Context, id string) (*RuleReceipt, error) {
	var v struct {
		Receipt *RuleReceipt `json:"receipt"`
	}
	e := c.call(ctx, "automatic-receipt", map[string]string{"requestId": id}, &v)
	return v.Receipt, e
}
