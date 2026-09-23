// Command scuttle-keygen prints a fresh scuttle key set as environment-style
// lines:
//
//	SCUTTLE_CAPTURE_SEED        PRIVATE. Readers only. Opens every row.
//	SCUTTLE_CAPTURE_PUBLIC_KEY  public. Every writer gets this.
//	SCUTTLE_KEM_KEY_ID          public. The generation id rows are stamped with.
//	SCUTTLE_AUTH_KEY            SECRET. Writers and readers; never stored with data.
//
// It writes to stdout only and keeps nothing. Redirect it straight into your
// secret manager rather than a file on a shared disk.
package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/Continuum-AI-Corp/scuttle"
)

func main() {
	if err := run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "scuttle-keygen:", err)
		os.Exit(1)
	}
}

func run(w io.Writer) error {
	seed, err := scuttle.GenerateCaptureSeed()
	if err != nil {
		return err
	}
	kr, err := scuttle.NewLocalKeyring(seed)
	if err != nil {
		return err
	}
	auth, err := scuttle.GenerateAuthKey()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, `# scuttle key set. The seed and the auth key are secrets.
# PRIVATE — readers only. Opens every row sealed under the public key below.
SCUTTLE_CAPTURE_SEED=%s
# Public — give this to every writer.
SCUTTLE_CAPTURE_PUBLIC_KEY=%s
SCUTTLE_KEM_KEY_ID=%s
# SECRET — writers and readers (Envelope.AuthKey). Never store it with the data.
SCUTTLE_AUTH_KEY=%s
`, hex.EncodeToString(seed), hex.EncodeToString(kr.CapturePublicKey()), kr.KemKeyID(), hex.EncodeToString(auth))
	return err
}
