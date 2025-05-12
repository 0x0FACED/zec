package progress

import (
	"fmt"
	"os"
	"time"

	"github.com/schollz/progressbar/v3"
)

func NewPrettyProgressBar(description string, size int64) *progressbar.ProgressBar {
	bar := progressbar.NewOptions64(
		size,
		progressbar.OptionSetDescription("[cyan]"+description+"[reset]"),
		progressbar.OptionSetWidth(30),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionSetElapsedTime(false),
		progressbar.OptionSetPredictTime(false),
		progressbar.OptionShowCount(),
		progressbar.OptionThrottle(10*time.Millisecond),
		progressbar.OptionSetWriter(os.Stdout),
		progressbar.OptionOnCompletion(func() {
			fmt.Println()
		}),
	)

	return bar
}

func NewStepBar(description string) *progressbar.ProgressBar {
	return progressbar.NewOptions(
		1,
		progressbar.OptionSetDescription(description),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(20),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionOnCompletion(func() {
			fmt.Println()
		}),
	)
}
