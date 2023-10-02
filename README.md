# Envs

`envs` is a simple tool to securely manage local environment variables.

When working with applications that are configured through environment variables
(e.g. based on the principles from https://12factor.net/), it is common to have
one or more collections of these, depending on the environment the application
is run against (e.g. locally or a staging environment), `envs` allow you to
easily manage collections of environment variables and inject the into you
application.

## Features

- Simple and easy to use
- Store variables in plain text files
- Easily encrypt files with sensitive information

## Installation

You can install `envs` directly from source with

```
go install github.com/madss/envs@latest
```

## Usage

### Environment files

You can store collections of environment variables in plain text files. The
format is similar to the output of `env`. Lines beginning with `#` and blank
lines are ignored.

```
# Content of myenv.txt
HOST=localhost
PORT=8080
CACHE_DIR=/tmp
```

To securely store sensitive information, you can use the `-e` flag to encrypt
the data (see below)

### Injecting environment variables

To inject environment variables from the file `myenv.txt` into the program `env`, run

```
envs -f myenv.txt env
```

You can specify multiple files, like

```
envs -f myenv.txt -f myotherenv.txt env
```

By default only the environment variables from the specified files are included.
If you need to include environment variables from the surrounding environment
(e.g. `$HOME`), use the `-i` flag:

```
envs -i -f myenv.txt env
```

To export environment variables, you can use the `-p` flag to print the
variables in a format suitable to `eval`.

```
eval $(envs -p -f myenv.txt)
```

### Encrypting sensitive information

`envs` can create encrypted environment files, for storing sensitive
information, using the `-e` flag. The user will be prompted for a password, and
the program will afterwards read the content from stdin. The format is the same
as described above. The encrypted data will be written to the specified file, or
to the console if no file is specified.

```
envs -e -f mysecrets.bin
```

Injecting environment variables from encrypted files, works the same way as with
regular files, except that the user will be prompted for a password for each
encrypted file.

To avoid having to enter the password all the time, it can be provided by the
environment variable `ENVS_PASSWORD` (but be careful not to leak it in your
shells history).
