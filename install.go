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
	var x bytes.Buffer
	xml.EscapeText(&x, []byte(dir))
	path := x.String()
	data := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>
<key>Label</key><string>local.route-monitor</string>
<key>ProgramArguments</key><array><string>%s/route-monitor</string><string>-data</string><string>%s</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>15</integer>
<key>ProcessType</key><string>Background</string><key>Umask</key><integer>63</integer>
<key>StandardOutPath</key><string>/dev/null</string><key>StandardErrorPath</key><string>/dev/null</string>
</dict></plist>`, path, path)
	return os.WriteFile(filepath.Join(home, "Library/LaunchAgents/local.route-monitor.plist"), []byte(data), 0600)
}
