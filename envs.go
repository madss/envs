package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/term"
)

const (
	// The magic number used to identify encrypted files
	magic = "\x00env"
	// The environment variable containing the password for encrypting and decrypting
	passwordEnvName = "ENVS_PASSWORD"
)

type Options struct {
	Files      FileList
	IncludeEnv bool
	Encrypt    bool
	Print      bool
}

func main() {
	var options Options
	flag.BoolVar(&options.Encrypt, "e", false, "create encrypted environment from stdin")
	flag.Var(&options.Files, "f", "configuration `file`")
	flag.BoolVar(&options.IncludeEnv, "i", false, "include surrounding environment")
	flag.BoolVar(&options.Print, "p", false, "print environment variable in a format suitable for eval")
	flag.Parse()

	var app App
	if err := app.Run(options, flag.Args()); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

type App struct{}

func (app *App) Run(options Options, args []string) error {
	var env []string

	// Encrypt environment if requested
	if options.Encrypt {
		if len(options.Files) > 1 {
			return errors.New("only one file can be encrypted at a time")
		}

		f := os.Stdin
		if len(options.Files) == 1 && options.Files[0] != "-" {
			var err error
			f, err = os.Create(options.Files[0])
			if err != nil {
				return fmt.Errorf("opening file for writing: %w", err)
			}
			defer f.Close()
		}

		password, err := app.readPassword("Password: ")
		if err != nil {
			return fmt.Errorf("reading password: %w", err)
		}

		env, err = app.encryptStdin(f, password)
		if err != nil {
			return fmt.Errorf("encrypting environment: %w", err)
		}
	}

	// Exit early if no command is provided
	if !options.Print && len(args) == 0 {
		return nil
	}

	// Load environment from the requested files (if not already loaded)
	if len(options.Files) > 0 && len(env) == 0 {
		for _, filename := range options.Files {
			fileEnv, err := app.readFile(filename)
			if err != nil {
				return fmt.Errorf("reading file %s: %w", filename, err)
			}
			env = append(env, fileEnv...)
		}
	}

	if options.Print {
		for _, e := range env {
			fmt.Printf("export %s\n", e)
		}
	}

	if len(args) > 0 {
		// Prepare the environment
		var cmdEnv []string
		if options.IncludeEnv {
			cmdEnv = os.Environ() // include the surrounding environment
		} else {
			cmdEnv = []string{} // use a non-nil value to force a clean environment
		}
		cmdEnv = append(cmdEnv, env...)

		// Run the command
		app.exec(args[0], args[1:], cmdEnv)
	}

	return nil
}

func (app *App) readPassword(prompt string, args ...any) ([]byte, error) {
	if password, ok := os.LookupEnv(passwordEnvName); ok {
		return []byte(password), nil
	}
	fmt.Printf(prompt, args...)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return password, err
}

func (app *App) encryptStdin(f io.Writer, password []byte) ([]string, error) {
	// Read all the data that should be encrypted
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("read environment from stdin: %w", err)
	}

	// Parse the environment
	env, err := app.parseEnv(data)
	if err != nil {
		return nil, fmt.Errorf("parsing environment: %w", err)
	}

	// Initialize the encryption algorithm
	gcm, err := app.createGCM(password)
	if err != nil {
		return nil, fmt.Errorf("initializing encryption algorithm: %w", err)
	}

	// Create a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	// Encrypt the data in-place
	data = gcm.Seal(data[:0], nonce, data, nil)

	// Write the encrypted data
	if _, err := f.Write([]byte(magic)); err != nil {
		return nil, fmt.Errorf("writing magic number: %w", err)
	}
	if _, err := f.Write(nonce); err != nil {
		return nil, fmt.Errorf("writing nonce: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return nil, fmt.Errorf("writing encrypted data: %w", err)
	}

	return env, nil
}

func (app *App) readFile(filename string) ([]string, error) {
	// Open file containing the environment
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("opening file for reading: %w", err)
	}

	// Handle encrypted environment
	if len(data) >= len(magic) && string(data[:len(magic)]) == magic {
		// discard magic header
		data = data[len(magic):]

		password, err := app.readPassword("Password for %s: ", filename)
		if err != nil {
			return nil, fmt.Errorf("reading password: %w", err)
		}

		data, err = app.decrypt(data, password)
		if err != nil {
			return nil, fmt.Errorf("decrypting environment: %w", err)
		}
	}

	env, err := app.parseEnv(data)
	if err != nil {
		return nil, fmt.Errorf("parsing environment: %w", err)
	}

	return env, nil
}

func (app *App) parseEnv(data []byte) ([]string, error) {
	var env []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("parsing environment: %w", err)
		}
		line := scanner.Text()

		// Skip empty lines and comments
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}

		elems := strings.SplitN(line, "=", 2)
		if len(elems) != 2 {
			return nil, fmt.Errorf("invalid line: %s", line)
		}

		env = append(env, fmt.Sprintf("%s=%s", elems[0], elems[1]))
	}
	return env, nil
}

func (app *App) decrypt(data, password []byte) ([]byte, error) {
	gcm, err := app.createGCM(password)
	if err != nil {
		return nil, fmt.Errorf("initializing encryption algorithm: %w", err)
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("data does not contain nonce")
	}
	var nonce []byte
	nonce, data = data[:gcm.NonceSize()], data[gcm.NonceSize():]

	data, err = gcm.Open(data[:0], nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return data, nil
}

func (app *App) createGCM(password []byte) (cipher.AEAD, error) {
	// Hash the password with a secure algorithm
	passwordHash := sha256.Sum256(password)

	// Initialize the AES block cipher
	block, err := aes.NewCipher(passwordHash[:])
	if err != nil {
		return nil, fmt.Errorf("initializing block cipher: %w", err)
	}

	// Initialize the gcm algorithm
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initializing gcm: %w", err)
	}

	return gcm, nil
}

func (app *App) exec(name string, args []string, env []string) error {
	// Prepare the given command with I/O and environment
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env

	// Run the command
	var exitErr *exec.ExitError
	if err := cmd.Run(); err != nil {
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("unexpected error while executing %s: %w", name, err)
	}
	return nil
}

type FileList []string

func (l *FileList) String() string {
	return strings.Join(*l, ",")
}

func (l *FileList) Set(file string) error {
	*l = append(*l, file)
	return nil
}
