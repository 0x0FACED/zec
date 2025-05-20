package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"math/bits"
	"os"
	"strings"
	"time"

	"github.com/0x0FACED/zec/pkg/core/v1/file"
	"github.com/0x0FACED/zec/pkg/core/v1/types"
	"github.com/0x0FACED/zlog"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
)

const (
	ColorReset        = "\033[0m"
	ColorCyan         = "\033[36m"    // Cyan
	ColorBlue         = "\033[34m"    // Blue
	ColorYellow       = "\033[33m"    // Yellow
	ColorRed          = "\033[31m"    // Red
	ColorMagenta      = "\033[35m"    // Magenta
	ColorBlackOnWhite = "\033[30;47m" // Black text on White BG
	ColorWhiteOnRed   = "\033[97;41m" // White text on Red BG
	ColorLightGray    = "\033[37m"    // Light gray
)

var logger *zlog.ZerologLogger
var rootCmd *cobra.Command

func main() {
	rootCmd = &cobra.Command{
		Use:   "zec",
		Short: "zec — a safe cli tool to store your secrets",
	}

	logger, _ = zlog.NewZerologLogger(zlog.LoggerConfig{
		LogLevel: "info",
	})

	rootCmd.AddCommand(completionCmd())
	rootCmd.AddCommand(newCmd())
	rootCmd.AddCommand(addCmd())
	rootCmd.AddCommand(getCmd())
	rootCmd.AddCommand(rmCmd())
	rootCmd.AddCommand(listCmd())
	rootCmd.AddCommand(headerCmd())

	if err := rootCmd.Execute(); err != nil {
		logger.Error().Err(err).Msg("Error occured")
		os.Exit(1)
	}
}

func completionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		// vibe coded long description
		Long: `To load completions:

Bash:

  $ source <(zec completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ zec completion bash > /etc/bash_completion.d/zec
  # macOS:
  $ zec completion bash > /usr/local/etc/bash_completion.d/zec

Zsh:

  # If shell completion is not already enabled in your environment,
  # you will need to enable it. You can execute the following once:

  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  $ zec completion zsh > "${fpath[1]}/_zec"

Fish:

  $ zec completion fish | source

  $ zec completion fish > ~/.config/fish/completions/zec.fish

PowerShell:

  PS> zec completion powershell | Out-String | Invoke-Expression

  # To load for every session:
  PS> zec completion powershell > zec.ps1
  # and source this file from your PowerShell profile.
`,
		Args:      cobra.MatchAll(cobra.ExactArgs(1)),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		Run: func(cmd *cobra.Command, args []string) {
			switch args[0] {
			case "bash":
				rootCmd.GenBashCompletion(os.Stdout)
			case "zsh":
				rootCmd.GenZshCompletion(os.Stdout)
			case "fish":
				rootCmd.GenFishCompletion(os.Stdout, true)
			case "powershell":
				rootCmd.GenPowerShellCompletion(os.Stdout)
			}
		},
	}
}

func newCmd() *cobra.Command {
	var file string

	cmd := &cobra.Command{
		Use:   "new",
		Short: "Create new file with secrets",
		RunE: func(cmd *cobra.Command, args []string) error {
			password := promptPassword("Enter password for file: ")
			path := file + ".zec"

			sf, err := types.NewSecretFile(path, []byte(password))
			if err != nil {
				return err
			}

			if err := sf.Save(); err != nil {
				return err
			}

			logger.Info().Str("file", path).Msg("File successfully created")
			return nil
		},
	}

	cmd.Flags().StringVar(&file, "file", "", "Filename without extension (necessary)")
	cmd.MarkFlagRequired("file") //nolint:errcheck

	return cmd
}

func addCmd() *cobra.Command {
	var filename, name, payload string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add secret to file",
		RunE: func(cmd *cobra.Command, args []string) error {
			password := promptPassword("Enter password: ")

			path := filename + ".zec"
			sf, err := file.Open(path, []byte(password))
			if err != nil {
				return err
			}

			if err := sf.ValidateChecksum(); err != nil {
				return err
			}

			var meta types.SecretMeta
			var reader io.Reader

			if isFile(payload) {
				f, err := os.Open(payload)
				if err != nil {
					return err
				}
				defer f.Close()

				stat, err := f.Stat()
				if err != nil {
					return err
				}

				meta, err = types.NewSecretMetaWithType(name, uint64(stat.Size()), types.File)
				if err != nil {
					return err
				}
				reader = f

				err = sf.WriteSecretFromReader(meta, reader)
				if err != nil {
					return err
				}
			} else {
				meta, err = types.NewSecretMetaWithType(name, uint64(len(payload)), types.PlainText)
				if err != nil {
					return err
				}
				reader = bytes.NewReader([]byte(payload))

				err = sf.WriteSecret(meta, reader)
				if err != nil {
					return err
				}
			}

			if err := sf.Save(); err != nil {
				return err
			}

			logger.Info().Str("file", path).Str("secret_name", name).Msg("Secret successfully added to file")
			return nil
		},
	}

	cmd.Flags().StringVar(&filename, "file", "", "Filename without extension (necessary)")
	cmd.Flags().StringVar(&name, "name", "", "Secret name (necessary)")
	cmd.Flags().StringVar(&payload, "payload", "", "Payload (text or path to file, necessary)")

	cmd.MarkFlagRequired("file")    //nolint:errcheck
	cmd.MarkFlagRequired("name")    //nolint:errcheck
	cmd.MarkFlagRequired("payload") //nolint:errcheck

	return cmd
}

func getCmd() *cobra.Command {
	var filename, name, out string

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get secret from file",
		RunE: func(cmd *cobra.Command, args []string) error {
			password := promptPassword("Enter password: ")

			path := filename + ".zec"
			sf, err := file.Open(path, []byte(password))
			if err != nil {
				return err
			}

			if err := sf.ValidateChecksum(); err != nil {
				return err
			}

			if out != "" {
				outFile, err := os.Create(out)
				if err != nil {
					return err
				}
				defer outFile.Close()

				err = sf.ReadSecretToWriter(name, outFile)
				if err != nil {
					return err
				}

				logger.Info().Str("file", path).Str("out", out).Str("secret_name", name).Msg("Secret exported")
				return nil
			}

			secret, err := sf.ReadSecret(name)
			if err != nil {
				return err
			}

			if err := sf.Close(); err != nil {
				return err
			}

			logger.Info().Msg(string(secret.Val))
			return nil
		},
	}

	cmd.Flags().StringVar(&filename, "file", "", "Filename without extension (necessary)")
	cmd.Flags().StringVar(&name, "name", "", "Secret name (necessary)")
	cmd.Flags().StringVar(&out, "out", "", "Filename of extracted secret file. If not provided - use stdout")

	cmd.MarkFlagRequired("file") //nolint:errcheck
	cmd.MarkFlagRequired("name") //nolint:errcheck

	return cmd
}

func rmCmd() *cobra.Command {
	var filename, name string
	var force bool

	cmd := &cobra.Command{
		Use:   "rm",
		Short: "Delete secret",
		RunE: func(cmd *cobra.Command, args []string) error {
			password := promptPassword("Enter password: ")

			path := filename + ".zec"
			sf, err := file.Open(path, []byte(password))
			if err != nil {
				return err
			}

			if err := sf.ValidateChecksum(); err != nil {
				return err
			}

			if force {
				err := sf.DeleteSecretForce(name)
				if err != nil {
					return err
				}

				logger.Info().Msg("Secret deleted, file formatted")
			} else {
				err := sf.DeleteSecretSoft(name)
				if err != nil {
					return err
				}

				logger.Info().Msg("Secret marked as deleted")
			}

			if err := sf.Save(); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&filename, "file", "", "Filename without extension (necessary)")
	cmd.Flags().StringVar(&name, "name", "", "Secret name (necessary)")
	cmd.Flags().BoolVar(&force, "force", false, "If force flag set - delete secret force. Soft delete by default")

	cmd.MarkFlagRequired("file") //nolint:errcheck
	cmd.MarkFlagRequired("name") //nolint:errcheck

	return cmd
}

func listCmd() *cobra.Command {
	var filename string
	var all bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List secrets info from file",
		RunE: func(cmd *cobra.Command, args []string) error {
			password := promptPassword("Enter password: ")

			path := filename + ".zec"
			sf, err := file.Open(path, []byte(password))
			if err != nil {
				return err
			}

			if err := sf.ValidateChecksum(); err != nil {
				return err
			}

			idxTable := sf.IndexTable()

			if err := sf.Close(); err != nil {
				return err
			}

			renderColoredSecretList(idxTable.Secrets, all)

			return nil
		},
	}

	cmd.Flags().StringVar(&filename, "file", "", "Filename without extension (necessary)")
	cmd.Flags().BoolVar(&all, "all", false, "Show all secrects (include marked as deleted)")

	cmd.MarkFlagRequired("file") //nolint:errcheck

	return cmd
}

func headerCmd() *cobra.Command {
	var filename string

	cmd := &cobra.Command{
		Use:   "header",
		Short: "Show header of file",
		RunE: func(cmd *cobra.Command, args []string) error {
			password := promptPassword("Enter password: ")

			path := filename + ".zec"
			sf, err := file.Open(path, []byte(password))
			if err != nil {
				return err
			}

			if err := sf.ValidateChecksum(); err != nil {
				return err
			}

			header := sf.Header()

			if err := sf.Close(); err != nil {
				return err
			}

			renderColoredHeader(&header)

			return nil
		},
	}

	cmd.Flags().StringVar(&filename, "file", "", "Filename without extension (necessary)")

	cmd.MarkFlagRequired("file") //nolint:errcheck

	return cmd
}

func promptPassword(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	password, _ := reader.ReadString('\n')
	return strings.TrimSpace(password)
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func renderColoredSecretList(secrets []types.SecretMeta, all bool) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleRounded)
	t.Style().Format.Header = text.FormatTitle
	t.Style().Format.HeaderAlign = text.AlignCenter
	t.Style().Format.RowAlign = text.AlignCenter
	t.Style().Color.Border = text.Colors{text.FgCyan}
	t.Style().Color.Separator = text.Colors{text.FgCyan}
	t.Style().Color.IndexColumn = text.Colors{text.FgCyan}
	t.Style().Color.Header = text.Colors{text.FgMagenta}
	t.Style().Color.Row = text.Colors{text.FgGreen}

	t.AppendHeader(table.Row{"Name", "Added at", "Last modified at", "Offset in file", "Size", "Type", "Encrypt Mode", "Flags"})

	for _, meta := range secrets {
		if !all {
			if meta.Flags&types.FlagDeleted != 0 {
				// marked as deleted
				continue
			}
		}

		createdTime := formatTimestamp(int64(meta.CreatedAt))
		modifiedTime := formatTimestamp(int64(meta.ModifiedAt))

		t.AppendRow(table.Row{
			string(meta.Name[:]),
			createdTime,
			modifiedTime,
			meta.Offset,
			readableSize(meta.Size),
			meta.TypeString(),
			meta.EncryptModeString(),
			meta.FlagsString(),
		})
	}

	t.Render()
}

func renderColoredHeader(h *types.Header) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleRounded)
	t.Style().Format.Header = text.FormatTitle
	t.Style().Format.HeaderAlign = text.AlignCenter
	t.Style().Color.Border = text.Colors{text.FgCyan}
	t.Style().Color.Separator = text.Colors{text.FgCyan}
	t.Style().Color.Header = text.Colors{text.FgMagenta}
	t.Style().Color.Row = text.Colors{text.FgGreen}

	t.AppendHeader(table.Row{"Header field", "Value"})
	t.AppendSeparator()

	// Main info
	t.AppendRows([]table.Row{
		{ColorRed + "Version" + ColorReset, fmt.Sprintf("0x%02X", h.Version)},
		{ColorRed + "Flags" + ColorReset, h.FlagsString()},
		{ColorRed + "Created At" + ColorReset, formatTimestamp(h.CreatedAt)},
		{ColorRed + "Last Modified At" + ColorReset, formatTimestamp(h.ModifiedAt)},
		{ColorRed + "Secret Count" + ColorReset, h.SecretCount},
		{ColorRed + "Data Size" + ColorReset, readableSize(h.DataSize)},
	})

	t.AppendSeparator()

	// Argon2 params
	t.AppendRows([]table.Row{
		{ColorRed + "Argon Memory" + ColorReset, readableSize(1 << h.ArgonMemoryLog2)},
		{ColorRed + "Argon Iterations" + ColorReset, h.ArgonIterations},
		{ColorRed + "Argon Parallelism" + ColorReset, h.ArgonParallelism},
		{ColorRed + "Argon Salt" + ColorReset, hex.EncodeToString(h.ArgonSalt[:])},
	})
	t.AppendSeparator()

	// Crypto params
	t.AppendRows([]table.Row{
		{ColorRed + "Encryption Algo" + ColorReset, h.EncryptionAlgo},
		{ColorRed + "Owner ID" + ColorReset, hex.EncodeToString(h.OwnerID[:])},
		{ColorRed + "Verification Tag" + ColorReset, hex.EncodeToString(h.VerificationTag[:])},
		{ColorRed + "Encrypted FEK" + ColorReset, fmt.Sprintf("%s...", hex.EncodeToString(h.EncryptedFEK[:32]))},
		{ColorRed + "Checksum (SHA-256)" + ColorReset, hex.EncodeToString(h.Checksum[:])},
	})
	t.AppendSeparator()

	// Other fields
	t.AppendRows([]table.Row{
		{ColorRed + "Index Table Offset" + ColorReset, h.IndexTableOffset},
		{ColorRed + "Index Table Nonce" + ColorReset, hex.EncodeToString(h.IndexTableNonce[:])},
	})

	t.Render()
}

func formatTimestamp(ts int64) string {
	unix := time.Unix(ts, 0)
	layout := "02 Jan 2006 15:04:05 MST"
	rfc1123zTime := unix.Format(layout)
	return rfc1123zTime
}

func readableSize(bytes uint64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d bytes", bytes)
	}

	base := uint(bits.Len64(bytes) / 10)
	val := float64(bytes) / float64(uint64(1<<(base*10)))

	return fmt.Sprintf("%.1f %ciB", val, " KMGTPE"[base])
}
