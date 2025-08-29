package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"math/bits"
	"os"
	"strings"
	"time"

	"github.com/0x0FACED/uuid"
	"github.com/0x0FACED/zec/pkg/zec"
	"github.com/0x0FACED/zec/pkg/zec/helpers"
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
		Use:   "zec2",
		Short: "zec2 — a safe cli tool to store your secrets (using pkg/zec)",
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
		Long: `To load completions:

Bash:

  $ source <(zec2 completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ zec2 completion bash > /etc/bash_completion.d/zec2
  # macOS:
  $ zec2 completion bash > /usr/local/etc/bash_completion.d/zec2

Zsh:

  # If shell completion is not already enabled in your environment,
  # you will need to enable it. You can execute the following once:

  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  $ zec2 completion zsh > "${fpath[1]}/_zec2"

Fish:

  $ zec2 completion fish | source

  $ zec2 completion fish > ~/.config/fish/completions/zec2.fish

PowerShell:

  PS> zec2 completion powershell | Out-String | Invoke-Expression

  # To load for every session:
  PS> zec2 completion powershell > zec2.ps1
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

			storage, err := zec.OpenFileStorage(path)
			if err != nil {
				return err
			}
			defer storage.Close()

			contID := uuid.NewV4()

			header, err := storage.GetHeader()
			if err != nil {
				return err
			}

			session, err := zec.NewSession(contID.String(), []byte(password), header)
			if err != nil {
				return err
			}
			defer session.Close()

			container, err := zec.NewContainer(storage, session, zec.DefaultContainerOptions())
			if err != nil {
				return err
			}
			defer container.Close()

			err = container.AddSecret(context.Background(), "test", bytes.NewBufferString("test"), zec.DefaultSecretOptions())
			if err != nil {
				return err
			}

			if err := container.ValidateIntegrity(); err != nil {
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

			storage, err := zec.OpenFileStorage(path)
			if err != nil {
				return err
			}

			contID := uuid.NewV4()

			header, err := storage.GetHeader()
			if err != nil {
				return err
			}

			session, err := zec.NewSession(contID.String(), []byte(password), header)
			if err != nil {
				return err
			}

			storage.SetSession(session)

			if err := storage.LoadIndex(); err != nil {
				return err
			}

			container, err := zec.OpenContainer(storage, session)
			if err != nil {
				return err
			}
			defer container.Close()

			if err := container.ValidateIntegrity(); err != nil {
				return err
			}

			var reader io.Reader
			var opts *zec.SecretOptions

			if isFile(payload) {
				f, err := os.Open(payload)
				if err != nil {
					return err
				}
				defer f.Close()
				reader = f
				opts = zec.FileSecretOptions()
			} else {
				reader = bytes.NewReader([]byte(payload))
				opts = zec.DefaultSecretOptions()
			}

			err = container.AddSecret(context.Background(), name, reader, opts)
			if err != nil {
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

			storage, err := zec.OpenFileStorage(path)
			if err != nil {
				return err
			}
			defer storage.Close()

			contID := uuid.NewV4()

			header, err := storage.GetHeader()
			if err != nil {
				return err
			}

			session, err := zec.NewSession(contID.String(), []byte(password), header)
			if err != nil {
				return err
			}
			defer session.Close()

			container, err := zec.OpenContainer(storage, session)
			if err != nil {
				return err
			}
			defer container.Close()

			if err := container.ValidateIntegrity(); err != nil {
				return err
			}

			secretReader, err := container.GetSecret(context.Background(), name)
			if err != nil {
				return err
			}
			defer secretReader.Close()

			if out != "" {
				outFile, err := os.Create(out)
				if err != nil {
					return err
				}
				defer outFile.Close()

				_, err = io.Copy(outFile, secretReader)
				if err != nil {
					return err
				}

				logger.Info().Str("file", path).Str("out", out).Str("secret_name", name).Msg("Secret exported")
			} else {
				secretData, err := io.ReadAll(secretReader)
				if err != nil {
					return err
				}

				logger.Info().Msg(string(secretData))
			}

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

			storage, err := zec.OpenFileStorage(path)
			if err != nil {
				return err
			}
			defer storage.Close()

			contID := uuid.NewV4()

			header, err := storage.GetHeader()
			if err != nil {
				return err
			}

			session, err := zec.NewSession(contID.String(), []byte(password), header)
			if err != nil {
				return err
			}
			defer session.Close()

			container, err := zec.OpenContainer(storage, session)
			if err != nil {
				return err
			}
			defer container.Close()

			if err := container.ValidateIntegrity(); err != nil {
				return err
			}

			err = container.DeleteSecret(name, force)
			if err != nil {
				return err
			}

			if force {
				logger.Info().Msg("Secret deleted, file formatted")
			} else {
				logger.Info().Msg("Secret marked as deleted")
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

			// Логика создания сессий должна в будущем быть вынесена
			// в агента. А здесь будет запрос через сокеты на создание
			// сессии и получение МК и FEK.
			storage, err := zec.OpenFileStorage(path)
			if err != nil {
				return err
			}
			defer storage.Close()

			contID := uuid.NewV4()

			header, err := storage.GetHeader()
			if err != nil {
				return err
			}

			session, err := zec.NewSession(contID.String(), []byte(password), header)
			if err != nil {
				return err
			}
			defer session.Close()

			storage.SetSession(session)

			if err := storage.LoadIndex(); err != nil {
				return err
			}

			container, err := zec.OpenContainer(storage, session)
			if err != nil {
				return err
			}
			defer container.Close()

			if err := container.ValidateIntegrity(); err != nil {
				return err
			}

			// Get secrets directly from storage to preserve all fields
			var metas []zec.SecretMeta
			if all {
				// If all flag is set, get full list including deleted ones from storage
				metas = storage.ListSecrets()
			} else {
				// Get only non-deleted secrets from container
				secrets := container.ListSecrets()
				metas = secrets
			}

			renderColoredSecretList(metas, all)

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

			storage, err := zec.OpenFileStorage(path)
			if err != nil {
				return err
			}
			defer storage.Close()

			contID := uuid.NewV4()

			header, err := storage.GetHeader()
			if err != nil {
				return err
			}

			session, err := zec.NewSession(contID.String(), []byte(password), header)
			if err != nil {
				return err
			}
			defer session.Close()

			container, err := zec.OpenContainer(storage, session)
			if err != nil {
				return err
			}
			defer container.Close()

			if err := container.ValidateIntegrity(); err != nil {
				return err
			}

			header, err = storage.GetHeader()
			if err != nil {
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

func renderColoredSecretList(secrets []zec.SecretMeta, all bool) {
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
			if meta.Flags&zec.FlagDeleted != 0 {
				continue
			}
		}

		createdTime := formatTimestamp(int64(meta.CreatedAt))
		modifiedTime := formatTimestamp(int64(meta.ModifiedAt))

		name := helpers.Bytes32ToString(meta.Name)

		t.AppendRow(table.Row{
			name,
			createdTime,
			modifiedTime,
			meta.Offset,
			readableSize(meta.Size),
			meta.Type.String(),
			meta.EncryptMode.String(),
			flagsString(meta.Flags),
		})
	}

	t.Render()
}

func renderColoredHeader(h *zec.Header) {
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

func flagsString(flags uint8) string {
	var result []string
	flagNames := map[uint8]string{
		zec.FlagUndefined:  "U",
		zec.FlagCompleted:  "C",
		zec.FlagEncrypted:  "E",
		zec.FlagCompressed: "X",
		zec.FlagDeleted:    "D",
	}

	for flag, name := range flagNames {
		if flags&flag != 0 {
			result = append(result, name)
		}
	}

	return strings.Join(result, "|")
}
