package routebridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
	"golang.org/x/sys/unix"
)

type coreRule struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
	Extra   struct {
		Disabled bool `json:"disabled"`
	} `json:"extra"`
}
type journalFile struct {
	Path    string `json:"path"`
	Backup  string `json:"backup"`
	New     string `json:"new"`
	Before  string `json:"before"`
	After   string `json:"after"`
	Existed bool   `json:"existed"`
}
type applyJournal struct {
	ID          string        `json:"id"`
	Stage       string        `json:"stage"`
	Previous    string        `json:"previous"`
	Files       []journalFile `json:"files"`
	BeforeRules []coreRule    `json:"beforeRules"`
	AfterRules  []coreRule    `json:"afterRules"`
	ConfigHash  string        `json:"configHash"`
}

func writeAtomic(path string, data []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".route-write-")
	if e != nil {
		return e
	}
	temp := f.Name()
	defer os.Remove(temp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(temp, path)
	}
	return e
}
func writeJSON(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return writeAtomic(path, b)
}
func readJSON(path string, v any) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return json.NewDecoder(io.LimitReader(f, 8<<20)).Decode(v)
}
func copyFile(from, to string) error {
	b, e := os.ReadFile(from)
	if e != nil {
		return e
	}
	return writeAtomic(to, b)
}

func ruleDelta(before, after []string, domain string) error {
	strip := func(rules []string) ([]string, map[string]int) {
		out := []string{}
		specific := map[string]int{}
		for _, r := range rules {
			if strings.HasPrefix(r, "DOMAIN,"+domain+",") {
				specific[r]++
			} else {
				out = append(out, r)
			}
		}
		return out, specific
	}
	b, bc := strip(before)
	a, ac := strip(after)
	if !reflect.DeepEqual(a, b) {
		return errors.New("rules_outside_domain")
	}
	added, removed := 0, 0
	keys := map[string]bool{}
	for k := range bc {
		keys[k] = true
	}
	for k := range ac {
		keys[k] = true
	}
	for k := range keys {
		d := ac[k] - bc[k]
		if d == 0 {
			continue
		}
		if k != "DOMAIN,"+domain+",DIRECT" && k != "DOMAIN,"+domain+",Proxies" {
			return errors.New("protected_domain_rule")
		}
		if d > 0 {
			added += d
		} else {
			removed -= d
		}
	}
	if added > 1 || removed > 1 {
		return errors.New("multiple_domain_changes")
	}
	return nil
}

func getCoreState(ctx context.Context, cfg map[string]any) ([]coreRule, string, error) {
	var r struct {
		Rules []coreRule `json:"rules"`
	}
	var settings map[string]any
	if e := api(ctx, cfg, http.MethodGet, "/rules", nil, &r); e != nil {
		return nil, "", e
	}
	if e := api(ctx, cfg, http.MethodGet, "/configs", nil, &settings); e != nil {
		return nil, "", e
	}
	return r.Rules, Hash(settings), nil
}

func expectedCore(before, after []string, old []coreRule) ([]coreRule, error) {
	if len(before) != len(old) {
		return nil, errors.New("runtime_file_mismatch")
	}
	known := map[string]coreRule{}
	for i, r := range before {
		known[r] = old[i]
	}
	out := make([]coreRule, len(after))
	for i, r := range after {
		v, ok := known[r]
		if ok {
			out[i] = v
			continue
		}
		p := strings.Split(r, ",")
		if len(p) != 3 || p[0] != "DOMAIN" || (p[2] != "DIRECT" && p[2] != "Router-Device-Egress") {
			return nil, errors.New("unexpected_generated_rule")
		}
		out[i] = coreRule{Type: "Domain", Payload: p[1], Proxy: p[2]}
	}
	return out, nil
}

const generateScript = `
CRASHDIR=$1
export CRASHDIR
[ -f "$CRASHDIR/configs/ShellCrash.cfg" ] && [ -f "$CRASHDIR/configs/command.env" ] || exit 10
. "$CRASHDIR/libs/get_config.sh"
. "$CRASHDIR/libs/logger.sh"
. "$CRASHDIR/libs/check_cmd.sh"
. "$CRASHDIR/libs/compare.sh"
ROOT=$CRASHDIR
TMPDIR="$2/run"
export TMPDIR
SC_CONFIG_INPUT="$2/input.yaml" CRASHDIR="$2/app" sh "$ROOT/tools/device-selectors.sh" || exit 11
CRASHDIR="$2/app"
core_config="$CRASHDIR/yamls/config.yaml"
SC_CONFIG_OUTPUT="$2/generated.yaml"
. "$ROOT/starts/clash_modify.sh"
modify_yaml || exit 12
[ -s "$SC_CONFIG_OUTPUT" ] || exit 12
`

func (b Bridge) generate(ctx context.Context, stage string, raw map[string]any, rules []string) (map[string]any, error) {
	for _, d := range []string{"app/yamls", "run"} {
		if e := os.MkdirAll(filepath.Join(stage, d), 0700); e != nil {
			return nil, errors.New("staging_failed")
		}
	}
	paths, e := filepath.Glob(filepath.Join(b.Root, "yamls/*.yaml"))
	if e != nil {
		return nil, e
	}
	for _, p := range paths {
		if e = copyFile(p, filepath.Join(stage, "app/yamls", filepath.Base(p))); e != nil {
			return nil, errors.New("staging_failed")
		}
	}
	if os.Symlink(filepath.Join(b.Root, "configs"), filepath.Join(stage, "app/configs")) != nil || os.Symlink(b.Core, filepath.Join(stage, "run/CrashCore")) != nil {
		return nil, errors.New("staging_failed")
	}
	newRaw := map[string]any{}
	for k, v := range raw {
		newRaw[k] = v
	}
	newRaw["rules"] = rules
	var encoded bytes.Buffer
	encoder := yaml.NewEncoder(&encoded)
	encoder.SetIndent(2)
	e = encoder.Encode(newRaw)
	encoder.Close()
	if e != nil {
		return nil, errors.New("invalid_candidate")
	}
	data := encoded.Bytes()
	if os.WriteFile(filepath.Join(stage, "input.yaml"), data, 0600) != nil {
		return nil, errors.New("staging_failed")
	}
	// Keep the saved-source checksum truthful after a rules-only update. The
	// original fetch provenance remains intact; this adds a separate edit time.
	meta, _ := os.ReadFile(filepath.Join(b.Root, "yamls/config.raw.meta"))
	lines := []string{}
	for _, line := range strings.Split(string(meta), "\n") {
		if line != "" && !strings.HasPrefix(line, "sha256=") && !strings.HasPrefix(line, "rules_updated_utc=") {
			lines = append(lines, line)
		}
	}
	h := sha256.Sum256(data)
	lines = append(lines, "sha256="+hex.EncodeToString(h[:]), "rules_updated_utc="+time.Now().UTC().Format(time.RFC3339))
	if os.WriteFile(filepath.Join(stage, "raw.meta"), []byte(strings.Join(lines, "\n")+"\n"), 0600) != nil {
		return nil, errors.New("staging_failed")
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", generateScript, "route-monitor", b.Root, stage)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return nil, errors.New("generation_failed")
	}
	var generated map[string]any
	if ReadYAML(filepath.Join(stage, "generated.yaml"), &generated) != nil {
		return nil, errors.New("generated_yaml_invalid")
	}
	check := exec.CommandContext(ctx, b.Core, "-t", "-d", b.Root, "-f", filepath.Join(stage, "generated.yaml"))
	check.Stdout = io.Discard
	check.Stderr = io.Discard
	if check.Run() != nil {
		return nil, errors.New("core_validation_failed")
	}
	return generated, nil
}

func (b Bridge) restore(ctx context.Context, j applyJournal, cfg map[string]any) error {
	if !b.validJournal(j) {
		return errors.New("invalid_apply_journal")
	}
	// Do not overwrite a concurrent external edit after a crash. Every affected
	// file and the live rules must still be one of this transaction's two states.
	for _, f := range j.Files {
		data, e := os.ReadFile(f.Path)
		if e != nil && !os.IsNotExist(e) {
			return errors.New("recovery_read_failed")
		}
		h := Hash(data)
		if h != f.Before && h != f.After {
			return errors.New("recovery_conflict")
		}
	}
	r, h, e := getCoreState(ctx, cfg)
	if e != nil || h != j.ConfigHash || (!reflect.DeepEqual(r, j.BeforeRules) && !reflect.DeepEqual(r, j.AfterRules)) {
		return errors.New("recovery_conflict")
	}
	data, _ := json.Marshal(map[string]string{"path": j.Previous})
	if api(ctx, cfg, http.MethodPut, "/configs?force=true", bytes.NewReader(data), nil) != nil {
		return errors.New("rollback_load_failed")
	}
	r, h, e = getCoreState(ctx, cfg)
	if e != nil || h != j.ConfigHash || !reflect.DeepEqual(r, j.BeforeRules) {
		return errors.New("rollback_readback_failed")
	}
	for _, f := range j.Files {
		if f.Existed {
			if copyFile(f.Backup, f.Path) != nil {
				return errors.New("rollback_file_failed")
			}
		} else {
			if e = os.Remove(f.Path); e != nil && !os.IsNotExist(e) {
				return errors.New("rollback_file_failed")
			}
		}
	}
	return nil
}

func (b Bridge) validJournal(j applyJournal) bool {
	if !ValidID(j.ID) || filepath.Dir(j.Stage) != filepath.Clean(b.Root) || !strings.HasPrefix(filepath.Base(j.Stage), ".route-monitor-apply-") || j.Previous != filepath.Join(j.Stage, "previous.yaml") {
		return false
	}
	info, e := os.Lstat(j.Stage)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	allowed := map[string]bool{b.Runtime: true}
	for _, name := range []string{"config.raw.yaml", "config.yaml", "others.yaml", "config.last-good.yaml", "config.raw.meta"} {
		allowed[filepath.Join(b.Root, "yamls", name)] = true
	}
	seen := map[string]bool{}
	for _, f := range j.Files {
		if !allowed[f.Path] || seen[f.Path] || filepath.Dir(f.Backup) != j.Stage || !strings.HasPrefix(filepath.Base(f.Backup), "backup-") || !strings.HasPrefix(filepath.Clean(f.New), j.Stage+string(os.PathSeparator)) {
			return false
		}
		seen[f.Path] = true
	}
	return len(j.Files) > 0 && len(j.BeforeRules) > 0 && len(j.AfterRules) > 0 && j.ConfigHash != ""
}

func (b Bridge) Apply(ctx context.Context, req Request) (Response, error) {
	if e := Validate(req); e != nil {
		return Response{}, e
	}
	lock, e := os.OpenFile(filepath.Join(filepath.Dir(b.Runtime), "config-update.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return Response{}, errors.New("lock_failed")
	}
	defer lock.Close()
	if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return Response{}, errors.New("configuration_busy")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	stateDir := filepath.Join(b.Root, ".route-monitor")
	if req.Operation == "apply" && os.MkdirAll(filepath.Join(stateDir, "receipts"), 0700) != nil {
		return Response{}, errors.New("state_unavailable")
	}
	journalPath := filepath.Join(stateDir, "active.json")
	receiptPath := filepath.Join(stateDir, "receipts", req.ID+".json")
	var previous Response
	if readJSON(receiptPath, &previous) == nil {
		s, e := b.Inspect(ctx)
		if e != nil || s.RawRulesHash != req.DesiredRulesHash {
			return Response{}, errors.New("apply_superseded")
		}
		var cfg map[string]any
		if ReadYAML(b.Runtime, &cfg) != nil {
			return Response{}, errors.New("config_unreadable")
		}
		actual, settings, e := getCoreState(ctx, cfg)
		if e != nil || Hash(actual) != previous.RuntimeHash || settings != previous.ConfigHash {
			return Response{}, errors.New("apply_superseded")
		}
		var pending applyJournal
		if req.Operation == "apply" && readJSON(journalPath, &pending) == nil && pending.ID == req.ID && b.validJournal(pending) {
			os.Remove(journalPath)
			os.RemoveAll(pending.Stage)
		}
		return previous, nil
	}
	var pending applyJournal
	if readJSON(journalPath, &pending) == nil {
		if req.Operation == "prepare" {
			return Response{}, errors.New("unfinished_apply")
		}
		if pending.ID != req.ID {
			return Response{}, errors.New("unfinished_apply")
		}
		if !b.validJournal(pending) {
			return Response{}, errors.New("invalid_apply_journal")
		}
		var recoveryConfig map[string]any
		if ReadYAML(pending.Previous, &recoveryConfig) != nil {
			return Response{}, errors.New("recovery_config_missing")
		}
		if e = b.restore(ctx, pending, recoveryConfig); e != nil {
			return Response{}, e
		}
		os.Remove(journalPath)
		os.RemoveAll(pending.Stage)
		return Response{}, errors.New("interrupted_apply_rolled_back")
	}
	if _, e = os.Stat(journalPath); e == nil || !os.IsNotExist(e) {
		return Response{}, errors.New("invalid_apply_journal")
	}
	runtime, raw, snap, e := b.load(ctx)
	if e != nil {
		return Response{}, e
	}
	if req.ExpectedSnapshot != "" && req.ExpectedSnapshot != snap.ID {
		return Response{}, errors.New("snapshot_changed")
	}
	if snap.RawRulesHash != req.ExpectedRulesHash || snap.RawNonRulesHash != req.ExpectedNonRulesHash {
		return Response{}, errors.New("subscription_drift")
	}
	oldRules, _ := stringRules(raw["rules"])
	if e = ruleDelta(oldRules, req.Rules, req.Domain); e != nil {
		return Response{}, e
	}
	if req.Action != "REMOVE" && protectedByLocal(snap.LocalRules, req.Domain) {
		return Response{}, errors.New("local_rule_protected")
	}
	if req.DesiredRulesHash == snap.RawRulesHash {
		actual, settings, e := getCoreState(ctx, runtime)
		if e != nil {
			return Response{}, e
		}
		out := Response{OK: true, Applied: req.Operation == "apply", ID: req.ID, Snapshot: snap, RuntimeHash: Hash(actual), ConfigHash: settings}
		if req.Operation == "apply" && writeJSON(receiptPath, out) != nil {
			return Response{}, errors.New("receipt_failed")
		}
		return out, nil
	}
	stage, e := os.MkdirTemp(b.Root, ".route-monitor-apply-")
	if e != nil {
		return Response{}, errors.New("staging_failed")
	}
	keep := false
	defer func() {
		if !keep {
			os.RemoveAll(stage)
		}
	}()
	generated, e := b.generate(ctx, stage, raw, req.Rules)
	if e != nil {
		return Response{}, e
	}
	if Hash(nonRules(generated)) != Hash(nonRules(runtime)) {
		return Response{}, errors.New("non_rules_changed")
	}
	var oldDevice, newDevice any
	if ReadYAML(filepath.Join(b.Root, "yamls/others.yaml"), &oldDevice) != nil || ReadYAML(filepath.Join(stage, "app/yamls/others.yaml"), &newDevice) != nil || Hash(oldDevice) != Hash(newDevice) {
		return Response{}, errors.New("device_policy_changed")
	}
	generatedRules, e := stringRules(generated["rules"])
	if e != nil {
		return Response{}, e
	}
	beforeRules, configHash, e := getCoreState(ctx, runtime)
	if e != nil {
		return Response{}, e
	}
	expected, e := expectedCore(snap.RuntimeRules, generatedRules, beforeRules)
	if e != nil {
		return Response{}, e
	}
	afterStage, e := b.Inspect(ctx)
	if e != nil || afterStage.ID != snap.ID {
		return Response{}, errors.New("snapshot_changed")
	}
	if req.Operation == "prepare" {
		return Response{OK: true, ID: req.ID, Snapshot: snap}, nil
	}
	if copyFile(b.Runtime, filepath.Join(stage, "previous.yaml")) != nil {
		return Response{}, errors.New("backup_failed")
	}
	j := applyJournal{ID: req.ID, Stage: stage, Previous: filepath.Join(stage, "previous.yaml"), BeforeRules: beforeRules, AfterRules: expected, ConfigHash: configHash}
	updates := [][2]string{{filepath.Join(stage, "input.yaml"), filepath.Join(b.Root, "yamls/config.raw.yaml")}, {filepath.Join(stage, "app/yamls/config.yaml"), filepath.Join(b.Root, "yamls/config.yaml")}, {filepath.Join(stage, "app/yamls/others.yaml"), filepath.Join(b.Root, "yamls/others.yaml")}, {filepath.Join(stage, "previous.yaml"), filepath.Join(b.Root, "yamls/config.last-good.yaml")}, {filepath.Join(stage, "generated.yaml"), b.Runtime}}
	updates = append(updates, [2]string{filepath.Join(stage, "raw.meta"), filepath.Join(b.Root, "yamls/config.raw.meta")})
	for i, pair := range updates {
		old, err := os.ReadFile(pair[1])
		if err != nil && !os.IsNotExist(err) {
			return Response{}, errors.New("backup_failed")
		}
		next, err := os.ReadFile(pair[0])
		if err != nil {
			return Response{}, errors.New("candidate_missing")
		}
		backup := filepath.Join(stage, "backup-"+string(rune('a'+i)))
		existed := old != nil
		if existed && os.WriteFile(backup, old, 0600) != nil {
			return Response{}, errors.New("backup_failed")
		}
		j.Files = append(j.Files, journalFile{Path: pair[1], New: pair[0], Backup: backup, Before: Hash(old), After: Hash(next), Existed: existed})
	}
	if writeJSON(journalPath, j) != nil {
		return Response{}, errors.New("journal_failed")
	}
	keep = true
	rollback := func(code string) (Response, error) {
		recovery, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if e := b.restore(recovery, j, runtime); e != nil {
			return Response{}, e
		}
		os.Remove(journalPath)
		keep = false
		return Response{}, errors.New(code)
	}
	body, _ := json.Marshal(map[string]string{"path": filepath.Join(stage, "generated.yaml")})
	if api(ctx, runtime, http.MethodPut, "/configs?force=true", bytes.NewReader(body), nil) != nil {
		return rollback("apply_failed_rolled_back")
	}
	actual, h, e := getCoreState(ctx, runtime)
	if e != nil || h != configHash || !reflect.DeepEqual(actual, expected) {
		return rollback("readback_failed_rolled_back")
	}
	for _, f := range j.Files {
		beforeCommit, err := os.ReadFile(f.Path)
		if (err != nil && !os.IsNotExist(err)) || Hash(beforeCommit) != f.Before {
			return rollback("concurrent_file_change")
		}
		if copyFile(f.New, f.Path) != nil {
			return rollback("commit_failed_rolled_back")
		}
	}
	final, e := b.Inspect(ctx)
	if e != nil || final.RawRulesHash != req.DesiredRulesHash || final.RawNonRulesHash != snap.RawNonRulesHash || !reflect.DeepEqual(final.Nodes, snap.Nodes) || !reflect.DeepEqual(final.InputsHash, snap.InputsHash) {
		return rollback("verification_failed_rolled_back")
	}
	out := Response{OK: true, Applied: true, ID: req.ID, Snapshot: final, RuntimeHash: Hash(actual), ConfigHash: configHash}
	if writeJSON(receiptPath, out) != nil {
		return rollback("receipt_failed_rolled_back")
	}
	os.Remove(journalPath)
	keep = false
	return out, nil
}
