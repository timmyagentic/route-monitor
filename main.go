package main

import (
	"bufio"
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/term"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed web/*
var assets embed.FS
var version = "0.5.2"

type Config struct {
	Router       string `json:"router"`
	Secret       string `json:"secret"`
	Listen       string `json:"listen"`
	Salt         string `json:"salt"`
	PasswordHash string `json:"passwordHash"`
}
type Health struct {
	Connected bool   `json:"connected"`
	Message   string `json:"message"`
}
type App struct {
	store       *Store
	router      *Router
	cfg         Config
	ctx         context.Context
	mu          sync.Mutex
	states      map[string]Health
	lastFrame   map[string]int64
	unparsed    int
	lookupIP    func(context.Context, string) ([]net.IPAddr, error)
	autoWake    chan struct{}
	bulkRunning bool
	probing     bool
	probeDomain string
	lastProbe   time.Time
	sessions    map[string]time.Time
	attempts    map[string][]time.Time
	subscribers map[chan struct{}]bool
}

func randomID() string {
	b := make([]byte, 24)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func hashPassword(password, salt string) string {
	key, e := pbkdf2.Key(sha256.New, password, []byte(salt), 200000, 32)
	if e != nil {
		panic(e)
	}
	return base64.StdEncoding.EncodeToString(key)
}
func configValid(c Config) error {
	u, e := url.Parse(c.Router)
	if e != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("路由器地址格式错误")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !(ip.IsPrivate() || ip.IsLoopback()) {
		return errors.New("路由器地址必须为局域网 IP")
	}
	if c.Secret == "" || c.Salt == "" || c.PasswordHash == "" {
		return errors.New("配置缺少密钥或页面密码")
	}
	if _, _, e = net.SplitHostPort(c.Listen); e != nil {
		return errors.New("监听地址格式错误")
	}
	return nil
}
func setup(path string) error {
	if _, e := os.Stat(path); e == nil {
		return errors.New("配置已存在，保留原配置；如需重配请先手动备份配置文件")
	}
	fmt.Println("分流体检：本机配置。密钥仅保存在此 Mac 的受限配置文件，不包含在安装包中。")
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("路由器 API 地址 [http://192.168.31.1:9999]: ")
	base, _ := reader.ReadString('\n')
	base = strings.TrimSpace(base)
	if base == "" {
		base = "http://192.168.31.1:9999"
	}
	readSecret := func(prompt string) (string, error) {
		fmt.Print(prompt)
		b, e := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		return strings.TrimSpace(string(b)), e
	}
	secret, e := readSecret("路由器代理后台管理密钥（输入不显示）: ")
	if e != nil {
		return e
	}
	password, e := readSecret("为分流体检设置页面访问密码（至少12字符，输入不显示）: ")
	if e != nil {
		return e
	}
	if len(password) < 12 {
		return errors.New("页面访问密码至少12字符")
	}
	confirm, e := readSecret("再输入一次页面密码: ")
	if e != nil {
		return e
	}
	if password != confirm {
		return errors.New("两次页面密码不同")
	}
	c := Config{Router: strings.TrimRight(base, "/"), Secret: secret, Listen: "0.0.0.0:9780", Salt: randomID()}
	c.PasswordHash = hashPassword(password, c.Salt)
	if e = configValid(c); e != nil {
		return e
	}
	var info map[string]any
	if _, e = newRouter(c.Router, c.Secret).get(context.Background(), "/version", &info); e != nil {
		return fmt.Errorf("验证路由器失败：%w", e)
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	data, _ := json.MarshalIndent(c, "", "  ")
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(data)
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}
func (a *App) health(kind string, ok bool, message string) {
	a.mu.Lock()
	previous, exists := a.states[kind]
	a.states[kind] = Health{ok, message}
	a.mu.Unlock()
	if !exists || previous != (Health{ok, message}) {
		log.Printf("health %s connected=%t %s", kind, ok, message)
	}
	a.publish()
	a.wakeAuto()
}
func (a *App) publish() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for ch := range a.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
func (a *App) authorized(r *http.Request) bool {
	c, e := r.Cookie("route_session")
	if e != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	until, ok := a.sessions[c.Value]
	return ok && time.Now().Before(until)
}
func (a *App) hostAllowed(hostport string) bool {
	host, port, e := net.SplitHostPort(hostport)
	if e != nil {
		return false
	}
	_, want, _ := net.SplitHostPort(a.cfg.Listen)
	if port != want {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		v, _, _ := net.ParseCIDR(addr.String())
		if v.Equal(ip) {
			return true
		}
	}
	return false
}
func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	reply(w, map[string]string{"error": message})
}
func (a *App) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.serviceHealth)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/app.js" && r.URL.Path != "/style.css" {
			http.NotFound(w, r)
			return
		}
		name := r.URL.Path
		if name == "/" {
			name = "/index.html"
		}
		data, e := assets.ReadFile("web" + name)
		if e != nil {
			http.NotFound(w, r)
			return
		}
		switch name {
		case "/index.html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		case "/app.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		case "/style.css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		}
		w.Write(data)
	})
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		now := time.Now()
		a.mu.Lock()
		recent := []time.Time{}
		for _, t := range a.attempts[ip] {
			if now.Sub(t) < 5*time.Minute {
				recent = append(recent, t)
			}
		}
		if len(recent) >= 10 {
			a.mu.Unlock()
			fail(w, 429, "尝试过于频繁，请5分钟后再试")
			return
		}
		a.attempts[ip] = append(recent, now)
		a.mu.Unlock()
		var input struct {
			Password string `json:"password"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input) != nil {
			fail(w, 400, "请求格式错误")
			return
		}
		hash := hashPassword(input.Password, a.cfg.Salt)
		if subtle.ConstantTimeCompare([]byte(hash), []byte(a.cfg.PasswordHash)) != 1 {
			fail(w, 401, "页面访问密码不正确（不是路由器密钥）")
			return
		}
		session := randomID()
		a.mu.Lock()
		for k, t := range a.sessions {
			if now.After(t) {
				delete(a.sessions, k)
			}
		}
		a.sessions[session] = now.Add(12 * time.Hour)
		a.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "route_session", Value: session, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
		reply(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/logout", func(w http.ResponseWriter, r *http.Request) {
		c, e := r.Cookie("route_session")
		if e == nil {
			a.mu.Lock()
			delete(a.sessions, c.Value)
			a.mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "route_session", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		reply(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) { a.sendState(w, r.URL.Query().Get("view")) })
	mux.HandleFunc("GET /api/detail", func(w http.ResponseWriter, r *http.Request) {
		domain := r.URL.Query().Get("domain")
		if domainName(domain) != domain || domain == "" {
			fail(w, 400, "域名格式错误")
			return
		}
		ps, e := a.store.probes(domain)
		if e != nil {
			fail(w, 500, "读取复测记录失败")
			return
		}
		rows, e := a.store.db.Query(`SELECT ts,source,route,rule,error FROM events WHERE domain=? AND kind='error' AND ts>? ORDER BY ts DESC LIMIT 30`, domain, time.Now().Unix()-86400)
		if e != nil {
			fail(w, 500, "读取错误记录失败")
			return
		}
		defer rows.Close()
		items := []map[string]any{}
		for rows.Next() {
			var ts int64
			var src, route, rule, err string
			if rows.Scan(&ts, &src, &route, &rule, &err) != nil {
				continue
			}
			items = append(items, map[string]any{"time": ts, "source": src, "route": route, "rule": rule, "error": err})
		}
		reply(w, map[string]any{"probes": ps, "errors": items})
	})
	mux.HandleFunc("POST /api/handling", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Domain                string `json:"domain"`
			Handled               *bool  `json:"handled"`
			Reason                string `json:"reason"`
			ExpectedErrorRevision *int64 `json:"expectedErrorRevision"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&input) != nil || domainName(input.Domain) != input.Domain || input.Domain == "" || input.Handled == nil || input.ExpectedErrorRevision == nil || *input.ExpectedErrorRevision < 0 {
			fail(w, 400, "请提供域名、处理状态及当前错误修订号")
			return
		}
		err := a.store.setHandled(input.Domain, *input.ExpectedErrorRevision, *input.Handled, input.Reason)
		switch {
		case errors.Is(err, errHandlingReason):
			fail(w, 400, err.Error())
			return
		case errors.Is(err, errHandlingConflict):
			fail(w, 409, err.Error())
			return
		case errors.Is(err, errDomainNotObserved):
			fail(w, 404, err.Error())
			return
		case err != nil:
			fail(w, 500, "保存处理状态失败")
			return
		}
		a.publish()
		reply(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/probe-pending", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		if a.probing || a.bulkRunning {
			a.mu.Unlock()
			fail(w, 409, "已有复测进行中")
			return
		}
		a.bulkRunning = true
		a.mu.Unlock()
		id, e := a.store.createBulk()
		if e != nil {
			a.mu.Lock()
			a.bulkRunning = false
			a.mu.Unlock()
			fail(w, 500, "无法建立批量复测")
			return
		}
		go a.runBulk(a.ctx, id)
		reply(w, a.store.bulkStatus())
	})
	mux.HandleFunc("GET /api/probe-pending", func(w http.ResponseWriter, r *http.Request) { reply(w, a.store.bulkResults()) })
	mux.HandleFunc("POST /api/probe", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Domain string `json:"domain"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&input) != nil {
			fail(w, 400, "请求格式错误")
			return
		}
		a.mu.Lock()
		if a.bulkRunning || a.probing || time.Since(a.lastProbe) < time.Minute {
			a.mu.Unlock()
			fail(w, 429, "一次只复测一个域名，间隔至少1分钟")
			return
		}
		a.probing = true
		a.probeDomain = input.Domain
		a.lastProbe = time.Now()
		a.mu.Unlock()
		abort := a.releaseProbe
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if e := a.safeTarget(ctx, input.Domain); e != nil {
			abort()
			fail(w, 400, e.Error())
			return
		}
		nodes, e := a.nodes(ctx)
		if e != nil {
			abort()
			fail(w, 400, e.Error())
			return
		}
		go a.runProbe(a.ctx, input.Domain, nodes)
		a.publish()
		reply(w, map[string]any{"ok": true, "nodes": nodes})
	})
	mux.HandleFunc("GET /api/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		f, ok := w.(http.Flusher)
		if !ok {
			return
		}
		ch := make(chan struct{}, 1)
		a.mu.Lock()
		a.subscribers[ch] = true
		a.mu.Unlock()
		defer func() { a.mu.Lock(); delete(a.subscribers, ch); a.mu.Unlock() }()
		fmt.Fprint(w, "event: refresh\ndata: {}\n\n")
		f.Flush()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ch:
				if !a.authorized(r) {
					fmt.Fprint(w, "event: expired\ndata: {}\n\n")
					f.Flush()
					return
				}
				if _, e := fmt.Fprint(w, "event: refresh\ndata: {}\n\n"); e != nil {
					return
				}
				f.Flush()
			}
		}
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if !a.hostAllowed(r.Host) {
			fail(w, 403, "仅允许通过本机或局域网 IP 访问")
			return
		}
		if r.Method != "GET" {
			if r.Header.Get("Origin") != "http://"+r.Host {
				fail(w, 403, "来源校验失败")
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/login" && !a.authorized(r) {
			fail(w, 401, "请先登录")
			return
		}
		mux.ServeHTTP(w, r)
	})
}
func (a *App) sendState(w http.ResponseWriter, view string) {
	if view == "" {
		view = "active"
	}
	if view != "active" && view != "handled" && view != "all" {
		fail(w, 400, "无效清单视图")
		return
	}
	rows, unknown, e := a.store.summaryFor(view)
	if e != nil {
		fail(w, 500, "读取数据库失败")
		return
	}
	auto, e := a.store.autoStatus(time.Now())
	if e != nil {
		fail(w, 500, "读取自动复测状态失败")
		return
	}
	bulk := a.store.bulkStatus()
	a.mu.Lock()
	states := make(map[string]Health)
	for k, v := range a.states {
		states[k] = v
	}
	frames := make(map[string]int64)
	for k, v := range a.lastFrame {
		frames[k] = v
	}
	result := map[string]any{"bulk": bulk, "samplesPerRoute": probeSamples, "auto": auto, "version": version, "view": view, "rows": rows, "unknown": unknown, "states": states, "lastFrame": frames, "unparsed": a.unparsed, "probing": a.probing, "probeDomain": a.probeDomain, "now": time.Now().Unix()}
	a.mu.Unlock()
	reply(w, result)
}
func main() {
	home, e := os.UserHomeDir()
	if e != nil {
		log.Fatal(e)
	}
	dir := flag.String("data", filepath.Join(home, "Library", "Application Support", "RouteMonitor"), "数据目录")
	doSetup := flag.Bool("setup", false, "交互配置")
	check := flag.Bool("check", false, "验证路由器连接")
	agent := flag.Bool("install-agent", false, "生成登录启动项")
	service := flag.Bool("service", false, "后台运行并记录有限的生命周期日志")
	flag.Parse()
	if *service {
		writer, err := openServiceLog(*dir)
		if err != nil {
			log.Fatal("无法打开后台运行日志")
		}
		defer writer.Close()
		log.SetOutput(writer)
		log.Printf("service starting version=%s pid=%d ppid=%d", version, os.Getpid(), os.Getppid())
	}
	path := filepath.Join(*dir, "config.json")
	if *agent {
		if e = installAgent(*dir); e != nil {
			log.Fatal(e)
		}
		return
	}
	if *doSetup {
		if e = setup(path); e != nil {
			log.Fatal(e)
		}
		fmt.Println("配置成功。")
		return
	}
	data, e := os.ReadFile(path)
	if e != nil {
		log.Fatal("请先运行安装.command 配置本机服务")
	}
	var cfg Config
	if json.Unmarshal(data, &cfg) != nil {
		log.Fatal("配置文件格式错误")
	}
	if e = configValid(cfg); e != nil {
		log.Fatal(e)
	}
	router := newRouter(cfg.Router, cfg.Secret)
	if *check {
		var v map[string]any
		if _, e = router.get(context.Background(), "/version", &v); e != nil {
			log.Fatal(e)
		}
		fmt.Println("路由器接口认证成功")
		return
	}
	os.Chmod(*dir, 0700)
	os.Chmod(path, 0600)
	store, e := openStore(filepath.Join(*dir, "history.db"))
	if e != nil {
		log.Fatal("无法打开历史数据库")
	}
	defer store.db.Close()
	os.Chmod(filepath.Join(*dir, "history.db"), 0600)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	a := &App{store: store, router: router, cfg: cfg, ctx: ctx, states: map[string]Health{}, lastFrame: map[string]int64{}, sessions: map[string]time.Time{}, attempts: map[string][]time.Time{}, subscribers: map[chan struct{}]bool{}, autoWake: make(chan struct{}, 1)}
	listener, e := net.Listen("tcp", cfg.Listen)
	if e != nil {
		log.Fatal("监听端口失败：", e)
	}
	if e = store.recoverBulk(); e != nil {
		log.Fatal("批量复测初始化失败")
	}
	if e = store.interruptAuto(time.Now()); e != nil {
		log.Fatal("自动复测恢复失败")
	}
	a.health("storage", true, "")
	a.resumeBulk(ctx)
	go a.autoLoop(ctx)
	go a.collect(ctx, "connections", "/connections?interval=5000")
	go a.collect(ctx, "logs", "/logs?level=warning")
	srv := &http.Server{Handler: a.handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		log.Print("service shutdown requested")
		shutdown, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		srv.Shutdown(shutdown)
	}()
	_, listenPort, _ := net.SplitHostPort(cfg.Listen)
	fmt.Printf("分流体检 %s 已启动：http://localhost:%s/\n", version, listenPort)
	if e = srv.Serve(listener); e != nil && !errors.Is(e, http.ErrServerClosed) {
		log.Fatal(e)
	}
	log.Print("service stopped")
}
