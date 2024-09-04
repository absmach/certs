// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"bytes"
	"testing"

	"github.com/absmach/certs/cli"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

type outputLog uint8

const (
	usageLog outputLog = iota
	errLog
	entityLog
	okLog
)

func executeCommand(t *testing.T, root *cobra.Command, args ...string) string {
	buffer := new(bytes.Buffer)
	root.SetOut(buffer)
	root.SetErr(buffer)
	root.SetArgs(args)
	err := root.Execute()
	assert.NoError(t, err, "Error executing command")
	return buffer.String()
}

func setFlags(rootCmd *cobra.Command) *cobra.Command {
	// Root Flags
	rootCmd.PersistentFlags().BoolVarP(
		&cli.RawOutput,
		"raw",
		"r",
		cli.RawOutput,
		"Enables raw output mode for easier parsing of output",
	)

	rootCmd.PersistentFlags().Uint64VarP(
		&cli.Limit,
		"limit",
		"l",
		10,
		"Limit query parameter",
	)

	rootCmd.PersistentFlags().Uint64VarP(
		&cli.Offset,
		"offset",
		"o",
		0,
		"Offset query parameter",
	)

	rootCmd.PersistentFlags().StringVarP(
		&cli.Name,
		"name",
		"n",
		"",
		"Name query parameter",
	)

	return rootCmd
}
