package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kkrypt0nn/argane/cmd/argane/commands"
	"github.com/kkrypt0nn/argane/internal/buildinfo"
	"github.com/kkrypt0nn/argane/internal/util"
	"golang.org/x/term"
)

func main() {
	commands.Execute()
	checkForUpdates()
}

func checkForUpdates() {
	if !term.IsTerminal(int(os.Stdout.Fd())) || buildinfo.Version == "dev" || strings.Contains(buildinfo.Version, "SNAPSHOT") {
		return
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get("https://argane.krypton.ninja/latest-version")
	if err != nil {
		return
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		util.LogError("Failed to read response body from update check")
		return
	}

	latestVersion := strings.TrimSpace(string(respBody))
	if latestVersion != buildinfo.Version {
		fmt.Println("") // (o)-(o)
		util.LogInfo(fmt.Sprintf("The currently installed version of Argane (%s) is outdated, consider upgrading to the latest version (%s)", buildinfo.Version, latestVersion))
	}
}
