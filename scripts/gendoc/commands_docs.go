package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/kkrypt0nn/argane/cmd/argane/commands"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

const commandsOutDir = "./www/src/content/docs/commands"
const commandsMarkdownHeader = `---
title: %s
description: %s
---
`

var fileToCommand = map[string]*cobra.Command{}

func genCommandsDocs() error {
	arganeCommand := commands.NewArganeCommand()
	indexCommands(arganeCommand)
	filePrepender := func(filename string) string {
		name := filepath.Base(filename)
		cmd, ok := fileToCommand[name]
		if !ok {
			return ""
		}
		title, description := cmd.CommandPath(), strings.TrimSpace(cmd.Short)
		return fmt.Sprintf(commandsMarkdownHeader, title, description)
	}

	err := doc.GenMarkdownTreeCustom(arganeCommand, commandsOutDir, filePrepender, func(s string) string { return s })
	if err != nil {
		return err
	}

	err = filepath.Walk(commandsOutDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		return removeTitleHeader(path)
	})
	if err != nil {
		return err
	}

	fmt.Println("Command documentation files have been successfully generated")
	return nil
}

func indexCommands(cmd *cobra.Command) {
	fileToCommand[strings.ReplaceAll(cmd.CommandPath(), " ", "_")+".md"] = cmd
	for _, c := range cmd.Commands() {
		indexCommands(c)
	}
}

func removeTitleHeader(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "## ") {
			lines = append(lines[:i], lines[i+1:]...)
			break
		}
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
}
