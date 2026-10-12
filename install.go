package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
)

func installAgent(dir string) error {
	home, e := os.UserHomeDir()
	if e != nil {
		return e
	}
	executable, e := os.Executable()
	if e != nil {
		return e
	}
	if filepath.Base(filepath.Dir(executable)) != "MacOS" || filepath.Base(filepath.Dir(filepath.Dir(executable))) != "Contents" {
		return fmt.Errorf("请使用已安装的 Route Monitor.app 生成启动项")
	}
	data := agentPlist(executable, dir)
	return os.WriteFile(filepath.Join(home, "Library/LaunchAgents/local.route-monitor.plist"), []byte(data), 0600)
}

func agentPlist(executable, dir string) string {
	escape := func(s string) string {
		var b bytes.Buffer
		xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	data := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>
<key>Label</key><string>local.route-monitor</string>
<key>ProgramArguments</key><array><string>%s</string><string>-data</string><string>%s</string><string>-service</string></array>
<key>AssociatedBundleIdentifiers</key><array><string>local.route-monitor</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>15</integer>
<key>ProcessType</key><string>Background</string><key>Umask</key><integer>63</integer>
<key>StandardOutPath</key><string>/dev/null</string><key>StandardErrorPath</key><string>/dev/null</string>
</dict></plist>`, escape(executable), escape(dir))
	return data
}
