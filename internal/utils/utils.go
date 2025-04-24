package utils

import (
	"os"
	"strings"
	"bufio"

	"golang.org/x/term"

	"github.com/ibrahimsql/aether/pkg/model"
)

func IndexOf(element string, data []string) int {
	for k, v := range data {
		if element == v {
			return k
		}
	}
	return -1 // not found
}

func DuplicatedResult(result []model.PoC, rst model.PoC) bool {
	types := make(map[string]struct{}, len(result))
	for _, v := range result {
		types[v.Type] = struct{}{}
	}
	_, exists := types[rst.Type]
	return exists
}

func ContainsFromArray(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}
	i := strings.Split(item, "(")[0]
	_, ok := set[i]
	return ok
}

func CheckPType(str string) bool {
	return !strings.Contains(str, "toBlind") && !strings.Contains(str, "toGrepping")
}

// IsAllowType is checking content-type
func IsAllowType(contentType string) bool {
	notScanningType := map[string]struct{}{
		"application/json":       {},
		"application/javascript": {},
		"text/javascript":        {},
		"text/plain":             {},
		"text/css":               {},
		"image/jpeg":             {},
		"image/png":              {},
		"image/bmp":              {},
		"image/gif":              {},
		"application/rss+xml":    {},
	}

	for n := range notScanningType {
		if strings.Contains(contentType, n) {
			return false
		}
	}
	return true
}

// GenerateTerminalWidthLine generates a string that fills the terminal width with the specified character
func GenerateTerminalWidthLine(char string) string {
	width := GetTerminalWidth() - 5
	return strings.Repeat(char, width)
}

// GetTerminalWidth returns the width of the terminal
func GetTerminalWidth() int {
	width := 80 // default width
	if term.IsTerminal(int(os.Stdout.Fd())) {
		termWidth, _, err := term.GetSize(int(os.Stdout.Fd()))
		if err == nil && termWidth > 0 {
			width = termWidth
		}
	}

	return width
}

// UniqueStringSlice returns a new slice with duplicate strings removed.
func UniqueStringSlice(input []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, v := range input {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}

// ReadLinesOrLiteral reads a file line by line into a string slice, or returns a slice with the input string if the file does not exist.
func ReadLinesOrLiteral(pathOrLiteral string) ([]string, error) {
	if _, err := os.Stat(pathOrLiteral); err == nil {
		file, err := os.Open(pathOrLiteral)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		var lines []string
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				lines = append(lines, line)
			}
		}
		return lines, scanner.Err()
	}
	// If not a file, treat as literal
	return []string{pathOrLiteral}, nil
}
