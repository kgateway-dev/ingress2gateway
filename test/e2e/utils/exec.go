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

package utils

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

func MustHaveBin(name string) {
	if _, err := exec.LookPath(name); err != nil {
		panic(fmt.Errorf("required binary %q not found in PATH", name))
	}
}

func MustRun(ctx context.Context, bin string, args ...string) {
	if err := Run(ctx, bin, args...); err != nil {
		panic(err)
	}
}

func Run(ctx context.Context, bin string, args ...string) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Printf("RUN: %s %s", bin, strings.Join(args, " "))
	return cmd.Run()
}

// RunIngress2Gateway runs ingress2gateway against the input file and returns the generated YAML output.
func RunIngress2Gateway(ctx context.Context, emitter, root, inputFile string) ([]byte, error) {
	cmd := exec.CommandContext(
		ctx,
		"go", "run", ".",
		"print",
		"--providers=ingress-nginx",
		fmt.Sprintf("--emitter=%s", emitter),
		"--input-file", inputFile,
	)
	cmd.Dir = root

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ingress2gateway command failed: %w\nstderr:\n%s", err, stderr.String())
	}

	return stdout.Bytes(), nil
}

func Kubectl(ctx context.Context, kubeContext string, args ...string) (string, error) {
	base := []string{"--context", kubeContext}
	base = append(base, args...)
	cmd := exec.CommandContext(ctx, "kubectl", base...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	log.Printf("KUBECTL: kubectl %s", strings.Join(base, " "))
	err := cmd.Run()
	out := stdout.String()
	if err != nil {
		if se := strings.TrimSpace(stderr.String()); se != "" {
			out = out + "\n" + se
		}
		return out, fmt.Errorf("kubectl %v: %w", args, err)
	}
	return out, nil
}

func MustKubectl(ctx context.Context, kubeContext string, args ...string) {
	out, err := Kubectl(ctx, kubeContext, args...)
	if err != nil {
		panic(fmt.Errorf("kubectl failed: %v\n%s", err, out))
	}
}

func MustKubectlApplyStdin(ctx context.Context, kubeContext, yaml string) {
	cmd := exec.CommandContext(ctx, "kubectl", "--context", kubeContext, "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(yaml)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Printf("KUBECTL: kubectl --context %s apply -f -", kubeContext)
	if err := cmd.Run(); err != nil {
		panic(fmt.Errorf("kubectl apply -f - failed: %w", err))
	}
}
