package buildinfo

import (
	"fmt"
	"runtime"
)

const ApplicationName = "argane"

var (
	Version   = "dev"
	BuildDate = ""
	GitCommit = "dev"
	GoVersion = runtime.Version()
	Platform  = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
	Compiler  = runtime.Compiler
)
