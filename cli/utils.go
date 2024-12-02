// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/absmach/certs"
	ctxsdk "github.com/absmach/certs/sdk"
	"github.com/fatih/color"
	"github.com/hokaccha/go-prettyjson"
	"github.com/spf13/cobra"
)

const fileMode = 0o644

var (
	// Limit query parameter.
	Limit uint64 = 10
	// Offset query parameter.
	Offset uint64 = 0
	// Name query parameter.
	Name string = ""
	// ConfigPath config path parameter.
	ConfigPath string = ""
	// RawOutput raw output mode.
	RawOutput bool = false
)

func logJSONCmd(cmd cobra.Command, iList ...interface{}) {
	for _, i := range iList {
		m, err := json.Marshal(i)
		if err != nil {
			logErrorCmd(cmd, err)
			return
		}

		pj, err := prettyjson.Format(m)
		if err != nil {
			logErrorCmd(cmd, err)
			return
		}

		fmt.Fprintf(cmd.OutOrStdout(), "\n%s\n\n", string(pj))
	}
}

func logUsageCmd(cmd cobra.Command, u string) {
	fmt.Fprintf(cmd.OutOrStdout(), color.YellowString("\nusage: %s\n\n"), u)
}

func logErrorCmd(cmd cobra.Command, err error) {
	boldRed := color.New(color.FgRed, color.Bold)
	boldRed.Fprintf(cmd.ErrOrStderr(), "\nerror: ")

	fmt.Fprintf(cmd.ErrOrStderr(), "%s\n\n", color.RedString(err.Error()))
}

func logOKCmd(cmd cobra.Command) {
	fmt.Fprintf(cmd.OutOrStdout(), "\n%s\n\n", color.BlueString("ok"))
}

func logSaveCertFiles(cmd cobra.Command, certBundle ctxsdk.CertificateBundle) {
	files := map[string][]byte{
		"ca.pem":   certBundle.CA,
		"cert.pem": certBundle.Certificate,
		"key.pem":  certBundle.PrivateKey,
	}

	for filename, content := range files {
		err := saveToFile(filename, content)
		if err != nil {
			logErrorCmd(cmd, err)
			return
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Saved %s\n", filename)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "\nAll certificate files have been saved successfully.\n")
}

func logSaveCAFiles(cmd cobra.Command, certBundle ctxsdk.CertificateBundle) {
	files := map[string][]byte{
		"ca.crt": certBundle.Certificate,
		"ca.key": certBundle.PrivateKey,
	}

	for filename, content := range files {
		err := saveToFile(filename, content)
		if err != nil {
			logErrorCmd(cmd, err)
			return
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Saved %s\n", filename)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "\nAll certificate files have been saved successfully.\n")
}

func logSaveCSRFiles(cmd cobra.Command, csr certs.CSR) {
	files := map[string][]byte{
		"file.csr": []byte(csr.CSR),
	}

	for filename, content := range files {
		err := saveToFile(filename, content)
		if err != nil {
			logErrorCmd(cmd, err)
			return
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Saved %s\n", filename)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "\nCSR file have been saved successfully.\n")
}

func saveToFile(filename string, content []byte) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	filePath := filepath.Join(cwd, filename)
	if err := os.WriteFile(filePath, content, fileMode); err != nil {
		return fmt.Errorf("failed to write file %s: %w", filename, err)
	}

	return nil
}
