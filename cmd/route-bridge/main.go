package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"route-monitor/internal/routebridge"
)

func main() {
	root := flag.String("root", "/data/other/ShellCrash", "ShellCrash directory")
	runtime := flag.String("runtime", "/tmp/ShellCrash/config.yaml", "running YAML")
	core := flag.String("core", "/tmp/ShellCrash/CrashCore", "Mihomo binary")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 70*time.Second)
	defer cancel()
	var req routebridge.Request
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, routebridge.MaxInput+1))
	decoder.DisallowUnknownFields()
	var out routebridge.Response
	var err error
	if decoder.Decode(&req) != nil {
		out.Code = "invalid_request"
	} else if err = routebridge.Validate(req); err == nil {
		b := routebridge.Bridge{Root: *root, Runtime: *runtime, Core: *core}
		switch req.Operation {
		case "inspect":
			out.Snapshot, err = b.Inspect(ctx)
			out.OK = err == nil
		case "probe":
			out, err = b.Probe(ctx, req)
		case "apply", "prepare":
			out, err = b.Apply(ctx, req)
		}
	}
	if err != nil {
		out.Code = err.Error()
		out.OK = false
	}
	json.NewEncoder(os.Stdout).Encode(out)
	if !out.OK {
		os.Exit(1)
	}
}
