package util

import "fmt"

type Status string

const (
	StatusPass Status = "PASS"
	StatusFail Status = "FAIL"
)

func PrintResult(
	status Status,
	ruleID string,
	origin string,
	resource string,
	messages []string,
) {
	const ruleWidth = 42
	paddedRuleID := fmt.Sprintf("%-*s", ruleWidth, ruleID)

	switch status {
	case StatusPass:
		fmt.Printf(
			"%s PASS %s %s%s (%s)%s\n",
			BgGreen+FgBlack,
			Reset,
			paddedRuleID,
			FgGray+resource+Reset,
			origin,
			Reset,
		)

	case StatusFail:
		fmt.Printf(
			"%s FAIL %s %s%s (%s)%s\n",
			BgBrightRed+FgWhite,
			Reset,
			paddedRuleID,
			FgGray+resource+Reset,
			origin,
			Reset,
		)
		for _, message := range messages {
			fmt.Printf("       ↳  %s\n", message)
		}
	}
}

func LogError(message string) {
	fmt.Printf("%s ERROR %s %s\n", BgRed+FgWhite, Reset, message)
}

func LogInfo(message string) {
	fmt.Printf("%s INFO %s %s\n", BgBlue+FgWhite, Reset, message)
}
