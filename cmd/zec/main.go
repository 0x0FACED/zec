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

var logger *zlog.ZerologLogger

func init() {
	logger, _ = zlog.NewZerologLogger(zlog.LoggerConfig{
		LogLevel: "info",
	})
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "zec",
		Short: "zec — a safe cli tool to store your secrets",
	}

	rootCmd.AddCommand(newCmd())
	rootCmd.AddCommand(addCmd())
	rootCmd.AddCommand(getCmd())
	rootCmd.AddCommand(listCmd())
	rootCmd.AddCommand(headerCmd())

	if err := rootCmd.Execute(); err != nil {
		logger.Error().Err(err).Msg("Error occured")
		os.Exit(1)
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
				fmt.Println("Error open file: ", err)
				return err
			}

			if err := sf.ValidateChecksum(); err != nil {
				fmt.Println("Error validate checksum: ", err)
				return err
			}

			var meta types.SecretMeta
			var reader io.Reader

			if isFile(payload) {
				f, err := os.Open(payload)
				if err != nil {
				}
				defer f.Close()

				stat, err := f.Stat()
				if err != nil {
				}

				meta, err = types.NewSecretMetaWithType(name, uint64(stat.Size()), types.File)
				if err != nil {
					return err
				}
				reader = f
			} else {
				meta, err = types.NewSecretMetaWithType(name, uint64(len(payload)), types.PlainText)
				if err != nil {
					return err
				}
				reader = bytes.NewReader([]byte(payload))
			}

			err = sf.WriteSecret(meta, reader)
			if err != nil {
				return err
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

func listCmd() *cobra.Command {
	var filename string

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

			renderSecretList(idxTable.Secrets)

			return nil
		},
	}

	cmd.Flags().StringVar(&filename, "file", "", "Filename without extension (necessary)")

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

			renderHeader(&header)

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

func renderSecretList(secrets []types.SecretMeta) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetTitle("Secrets")
	t.SetStyle(table.StyleRounded)
	t.Style().Format.Header = text.FormatTitle

	t.AppendHeader(table.Row{"ID", "Created At", "Modified At", "Offset in file", "Size", "Type", "Flags"})

	for _, meta := range secrets {
		createdTime := formatTimestamp(int64(meta.CreatedAt))
		modifiedTime := formatTimestamp(int64(meta.ModifiedAt))

		t.AppendRow(table.Row{
			string(meta.ID[:]),
			createdTime,
			modifiedTime,
			meta.Offset,
			readableSize(meta.Size),
			meta.Type,
			meta.Flags,
		})
	}

	t.Render()
}

func renderHeader(h *types.Header) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleRounded)
	t.Style().Format.Header = text.FormatTitle

	t.AppendRow(table.Row{"Field", "Value"})
	t.AppendSeparator()

	// Main info
	t.AppendRows([]table.Row{
		{"Version", fmt.Sprintf("0x%02X", h.Version)},
		{"CompleteFlag", h.CompleteFlag},
		{"Created At", formatTimestamp(h.CreatedAt)},
		{"Modified At", formatTimestamp(h.ModifiedAt)},
		{"Secret Count", h.SecretCount},
		{"Data Size", readableSize(h.DataSize)},
	})
	t.AppendSeparator()

	// Argon2 params
	t.AppendRows([]table.Row{
		{"Argon Memory", readableSize(1 << h.ArgonMemoryLog2)},
		{"Argon Iterations", h.ArgonIterations},
		{"Argon Parallelism", h.ArgonParallelism},
		{"Argon Salt", hex.EncodeToString(h.ArgonSalt[:])},
	})
	t.AppendSeparator()

	// Crypto params
	t.AppendRows([]table.Row{
		{"Encryption Algo", h.EncryptionAlgo},
		{"Owner ID", hex.EncodeToString(h.OwnerID[:])},
		{"Verification Tag", hex.EncodeToString(h.VerificationTag[:])},
		{"Encrypted FEK", fmt.Sprintf("%s...", hex.EncodeToString(h.EncryptedFEK[:32]))},
		{"Checksum (SHA-256)", hex.EncodeToString(h.Checksum[:])},
	})
	t.AppendSeparator()

	// Other fields
	t.AppendRows([]table.Row{
		{"Index Table Offset", h.IndexTableOffset},
		{"Index Table Nonce", hex.EncodeToString(h.IndexTableNonce[:])},
	})

	t.Render()
}

func formatTimestamp(ts int64) string {
	unix := time.Unix(ts, 0)
	rfc1123zTime := unix.Format(time.RFC1123Z)
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
