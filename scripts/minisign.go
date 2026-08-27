package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	sigAlgEd        = "Ed"
	pubKeyLen       = 42
	sigPart1Len     = 74
	sigPart2Len     = 64
	untrustedPrefix = "untrusted comment: "
	trustedPrefix   = "trusted comment: "
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "keygen":
		if err := runKeygen(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "minisign keygen error: %v\n", err)
			os.Exit(1)
		}
	case "sign":
		if err := runSign(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "minisign sign error: %v\n", err)
			os.Exit(1)
		}
	case "verify":
		if err := runVerify(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "minisign verify error: %v\n", err)
			os.Exit(1)
		}
	case "-h", "--help", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`SendBeam Minisign Tool (Ed25519)

Usage:
  minisign keygen [-p pubkey.pub] [-s secret.key]
  minisign sign -m <file> [-s <secret-key-or-seed>] [-x <sig-file>] [-t <trusted-comment>]
  minisign verify -m <file> [-p <pubkey-file-or-key>] [-x <sig-file>] [-q]

Environment Variables:
  MINISIGN_SECRET_KEY   32-byte hex seed or raw secret key string for signing`)
}

// runKeygen generates a new minisign Ed25519 keypair.
func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	pubFile := fs.String("p", "minisign.pub", "public key output file")
	secFile := fs.String("s", "minisign.key", "secret key output file")
	_ = fs.Parse(args)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	var keyID [8]byte
	if _, err := rand.Read(keyID[:]); err != nil {
		return fmt.Errorf("failed to generate key id: %w", err)
	}

	keyIDHex := fmt.Sprintf("%016X", binary.LittleEndian.Uint64(keyID[:]))
	pubB64 := formatPublicKey(keyID[:], pub)
	pubContent := fmt.Sprintf("%sminisign public key %s\n%s\n", untrustedPrefix, keyIDHex, pubB64)

	if *pubFile != "" {
		if err := os.WriteFile(*pubFile, []byte(pubContent), 0644); err != nil {
			return fmt.Errorf("failed to write pubkey file: %w", err)
		}
		fmt.Printf("Public key written to %s\n", *pubFile)
	}

	seedHex := hex.EncodeToString(priv.Seed())
	secContent := fmt.Sprintf("%sminisign secret key seed (%s)\n%s\n", untrustedPrefix, keyIDHex, seedHex)
	if *secFile != "" {
		if err := os.WriteFile(*secFile, []byte(secContent), 0600); err != nil {
			return fmt.Errorf("failed to write secret key file: %w", err)
		}
		fmt.Printf("Secret key seed written to %s (keep secure)\n", *secFile)
	}

	fmt.Printf("\nKey ID: %s\n", keyIDHex)
	fmt.Printf("Public Key: %s\n", pubB64)
	fmt.Printf("Secret Key Seed (hex): %s\n", seedHex)
	return nil
}

// runSign signs a message file with a minisign secret key.
func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	msgFile := fs.String("m", "", "file to sign")
	secInput := fs.String("s", "", "secret key file or 32-byte hex seed")
	pubInput := fs.String("p", "", "matching public key file (default: minisign.pub if present)")
	sigFile := fs.String("x", "", "output signature file (default: <file>.minisig)")
	trustedComment := fs.String("t", "", "trusted comment")
	_ = fs.Parse(args)

	if *msgFile == "" {
		return errors.New("missing required -m <file> argument")
	}

	secretKeyStr := *secInput
	if secretKeyStr == "" {
		secretKeyStr = os.Getenv("MINISIGN_SECRET_KEY")
	}
	if secretKeyStr == "" {
		return errors.New("missing secret key: specify via -s or MINISIGN_SECRET_KEY environment variable")
	}

	privKey, err := parsePrivateKey(secretKeyStr)
	if err != nil {
		return fmt.Errorf("failed to parse secret key: %w", err)
	}

	content, err := os.ReadFile(*msgFile)
	if err != nil {
		return fmt.Errorf("failed to read message file: %w", err)
	}

	pubKey := privKey.Public().(ed25519.PublicKey)
	var keyID []byte

	pubKeyFile := *pubInput
	if pubKeyFile == "" {
		if _, err := os.Stat("minisign.pub"); err == nil {
			pubKeyFile = "minisign.pub"
		}
	}
	if pubKeyFile != "" {
		_, pKeyID, err := parsePublicKey(pubKeyFile)
		if err == nil && len(pKeyID) == 8 {
			keyID = pKeyID
		}
	}
	if len(keyID) != 8 {
		derived := deriveKeyID(pubKey)
		keyID = derived[:]
	}

	fileSig := ed25519.Sign(privKey, content)

	// Format line 2: 'E', 'd' + keyID (8 bytes) + fileSig (64 bytes)
	var sig1Raw [sigPart1Len]byte
	sig1Raw[0] = 'E'
	sig1Raw[1] = 'd'
	copy(sig1Raw[2:10], keyID)
	copy(sig1Raw[10:], fileSig)
	sig1B64 := base64.StdEncoding.EncodeToString(sig1Raw[:])

	// Format line 3: trusted comment
	tComment := *trustedComment
	if tComment == "" {
		tComment = fmt.Sprintf("timestamp:%d\tfile:%s", time.Now().Unix(), filepath.Base(*msgFile))
	}

	// Format line 4: global signature over (fileSig + trustedComment)
	globalData := append(append([]byte(nil), fileSig...), []byte(tComment)...)
	globalSig := ed25519.Sign(privKey, globalData)
	globalSigB64 := base64.StdEncoding.EncodeToString(globalSig)

	sigContent := fmt.Sprintf("%ssignature from minisign secret key\n%s\n%s%s\n%s\n",
		untrustedPrefix, sig1B64, trustedPrefix, tComment, globalSigB64)

	outFile := *sigFile
	if outFile == "" {
		outFile = *msgFile + ".minisig"
	}

	if err := os.WriteFile(outFile, []byte(sigContent), 0644); err != nil {
		return fmt.Errorf("failed to write signature file: %w", err)
	}

	fmt.Printf("Signature written to %s\n", outFile)
	return nil
}

// runVerify verifies a message file against a minisign signature.
func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	msgFile := fs.String("m", "", "file to verify")
	pubInput := fs.String("p", "", "public key file or base64 string (default: minisign.pub)")
	sigFile := fs.String("x", "", "signature file (default: <file>.minisig)")
	quiet := fs.Bool("q", false, "quiet mode")
	_ = fs.Parse(args)

	if *msgFile == "" {
		return errors.New("missing required -m <file> argument")
	}

	pubKeyStr := *pubInput
	if pubKeyStr == "" {
		if _, err := os.Stat("minisign.pub"); err == nil {
			pubKeyStr = "minisign.pub"
		} else {
			return errors.New("missing public key: specify via -p or provide minisign.pub")
		}
	}

	pubKey, expectedKeyID, err := parsePublicKey(pubKeyStr)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	inFile := *sigFile
	if inFile == "" {
		inFile = *msgFile + ".minisig"
	}

	sigBytes, err := os.ReadFile(inFile)
	if err != nil {
		return fmt.Errorf("failed to read signature file %s: %w", inFile, err)
	}

	content, err := os.ReadFile(*msgFile)
	if err != nil {
		return fmt.Errorf("failed to read message file %s: %w", *msgFile, err)
	}

	sigLines := strings.Split(strings.TrimSpace(string(sigBytes)), "\n")
	if len(sigLines) < 4 {
		return fmt.Errorf("malformed signature file: expected 4 lines, got %d", len(sigLines))
	}

	sig1Raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigLines[1]))
	if err != nil || len(sig1Raw) != sigPart1Len {
		return fmt.Errorf("invalid signature part 1 format (len=%d)", len(sig1Raw))
	}

	if sig1Raw[0] != 'E' || sig1Raw[1] != 'd' {
		return errors.New("unsupported signature algorithm (must be Ed)")
	}

	sigKeyID := sig1Raw[2:10]
	if len(expectedKeyID) == 8 && !bytes.Equal(sigKeyID, expectedKeyID) {
		return fmt.Errorf("key ID mismatch: signature has %x, public key has %x", sigKeyID, expectedKeyID)
	}

	fileSig := sig1Raw[10:74]
	if !ed25519.Verify(pubKey, content, fileSig) {
		return errors.New("file content signature verification failed: signature does not match content")
	}

	if !strings.HasPrefix(sigLines[2], trustedPrefix) {
		return errors.New("malformed trusted comment line")
	}
	trustedComment := strings.TrimPrefix(sigLines[2], trustedPrefix)

	globalSigRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigLines[3]))
	if err != nil || len(globalSigRaw) != sigPart2Len {
		return fmt.Errorf("invalid global signature format (len=%d)", len(globalSigRaw))
	}

	globalData := append(append([]byte(nil), fileSig...), []byte(trustedComment)...)
	if !ed25519.Verify(pubKey, globalData, globalSigRaw) {
		return errors.New("trusted comment signature verification failed: signature tampered")
	}

	if !*quiet {
		fmt.Printf("Signature and comment verified using public key ID %016X\n", binary.LittleEndian.Uint64(sigKeyID))
		fmt.Printf("Trusted comment: %s\n", trustedComment)
		fmt.Println("OK")
	}

	return nil
}

func formatPublicKey(keyID []byte, pub ed25519.PublicKey) string {
	var pubRaw [pubKeyLen]byte
	pubRaw[0] = 'E'
	pubRaw[1] = 'd'
	copy(pubRaw[2:10], keyID)
	copy(pubRaw[10:], pub)
	return base64.StdEncoding.EncodeToString(pubRaw[:])
}

func parsePublicKey(input string) (ed25519.PublicKey, []byte, error) {
	s := strings.TrimSpace(input)
	if data, err := os.ReadFile(s); err == nil {
		s = strings.TrimSpace(string(data))
	}

	lines := strings.Split(s, "\n")
	var b64 string
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if !strings.HasPrefix(trimmed, untrustedPrefix) && trimmed != "" {
			b64 = trimmed
			break
		}
	}
	if b64 == "" {
		return nil, nil, errors.New("no public key line found")
	}

	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	if len(raw) == 32 {
		return ed25519.PublicKey(raw), nil, nil
	}
	if len(raw) == pubKeyLen {
		if raw[0] != 'E' || raw[1] != 'd' {
			return nil, nil, errors.New("unsupported signature algorithm in pubkey")
		}
		keyID := raw[2:10]
		pub := ed25519.PublicKey(raw[10:])
		return pub, keyID, nil
	}

	return nil, nil, fmt.Errorf("unexpected public key length: %d", len(raw))
}

func parsePrivateKey(input string) (ed25519.PrivateKey, error) {
	s := strings.TrimSpace(input)
	if data, err := os.ReadFile(s); err == nil {
		s = strings.TrimSpace(string(data))
	}

	lines := strings.Split(s, "\n")
	var keyText string
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if !strings.HasPrefix(trimmed, untrustedPrefix) && trimmed != "" {
			keyText = trimmed
			break
		}
	}
	if keyText == "" {
		return nil, errors.New("no secret key content found")
	}

	if len(keyText) == 64 {
		seed, err := hex.DecodeString(keyText)
		if err == nil && len(seed) == 32 {
			return ed25519.NewKeyFromSeed(seed), nil
		}
	}

	if len(keyText) == 128 {
		full, err := hex.DecodeString(keyText)
		if err == nil && len(full) == 64 {
			return ed25519.PrivateKey(full), nil
		}
	}

	if raw, err := base64.StdEncoding.DecodeString(keyText); err == nil {
		if len(raw) == 32 {
			return ed25519.NewKeyFromSeed(raw), nil
		}
		if len(raw) == 64 {
			return ed25519.PrivateKey(raw), nil
		}
	}

	return nil, errors.New("unrecognized private key format (expected 32-byte hex seed or base64)")
}

func deriveKeyID(pub ed25519.PublicKey) [8]byte {
	var id [8]byte
	copy(id[:], pub[:8])
	return id
}
