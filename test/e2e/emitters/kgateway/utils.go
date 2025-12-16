/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package kgateway

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

func kgatewayVersionFromGoMod(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "go", "env", "GOMOD").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("go env GOMOD: %w: %s", err, string(out))
	}
	goModPath := strings.TrimSpace(string(out))
	if goModPath == "" || goModPath == os.DevNull {
		return "", fmt.Errorf("GOMOD not set (are you running in module mode?)")
	}
	b, err := os.ReadFile(goModPath)
	if err != nil {
		return "", err
	}

	re := regexp.MustCompile(`(?m)^\s*github\.com/kgateway-dev/kgateway/v2\s+([^\s]+)\s*$`)
	m := re.FindStringSubmatch(string(b))
	if len(m) != 2 {
		return "", fmt.Errorf("module github.com/kgateway-dev/kgateway/v2 not found in %s", goModPath)
	}

	modVer := m[1]

	// Trim Go pseudo-version suffix: .<timestamp>-<sha>
	modVer = regexp.MustCompile(`\.\d{14}-[0-9a-f]{7,}$`).ReplaceAllString(modVer, "")

	// kgateway beta releases drop the trailing ".0" in their chart/release tags.
	modVer = regexp.MustCompile(`(v[0-9]+\.[0-9]+\.[0-9]+-beta\.[0-9]+)\.0$`).ReplaceAllString(modVer, `$1`)

	return modVer, nil
}

func envOrDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func pickLBRange(cidr string, count uint32) (net.IP, net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, nil, fmt.Errorf("only IPv4 supported, got %s", cidr)
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, nil, fmt.Errorf("unexpected mask bits: %d", bits)
	}
	total := uint32(1) << uint32(32-ones)
	if total < count+10 {
		return nil, nil, fmt.Errorf("subnet too small for lb range: %s", cidr)
	}

	base := binary.BigEndian.Uint32(ipnet.IP.To4())
	last := base + total - 2
	first := last - count

	start := make(net.IP, 4)
	end := make(net.IP, 4)
	binary.BigEndian.PutUint32(start, first)
	binary.BigEndian.PutUint32(end, last)

	if !ipnet.Contains(start) || !ipnet.Contains(end) {
		return nil, nil, fmt.Errorf("computed range not within subnet: %s-%s not in %s", start, end, cidr)
	}
	return start, end, nil
}

func moduleRoot(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "go", "env", "GOMOD").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("go env GOMOD: %w: %s", err, string(out))
	}
	goMod := strings.TrimSpace(string(out))
	if goMod == "" || goMod == os.DevNull {
		return "", fmt.Errorf("GOMOD not set")
	}
	return filepath.Dir(goMod), nil
}
