// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import "strings"

// NormalizeSerialNumber normalizes a serial number to use colon-separated hex format.
func NormalizeSerialNumber(serial string) string {
	cleaned := strings.ReplaceAll(strings.ReplaceAll(serial, ":", ""), " ", "")

	cleaned = strings.ToLower(cleaned)

	if len(cleaned)%2 != 0 {
		cleaned = "0" + cleaned
	}

	var result strings.Builder
	for i := 0; i < len(cleaned); i += 2 {
		if i > 0 {
			result.WriteString(":")
		}
		result.WriteString(cleaned[i : i+2])
	}

	return result.String()
}
