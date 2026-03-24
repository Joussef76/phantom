package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

//ANSI Colors

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
)

// ─── Constants ───────────────────────────────────────────────────────────────

const (
	magic       = "JRF7"
	version     = byte(3)
	bufferSize  = 4 * 1024 * 1024
	chunkSize   = 1 * 1024 * 1024
	maxAttempts = 3

	// argon2id  OWASP recommended minimums
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32

	hmacSaltLen = 16
	hmacLen     = 32

	slotReal  = byte(0xAA)
	slotDecoy = byte(0x55)
)

func logInfo(msg string)    { fmt.Println(ColorCyan + "[*] " + msg + ColorReset) }
func logSuccess(msg string) { fmt.Println(ColorGreen + "[✔] " + msg + ColorReset) }
func logWarn(msg string)    { fmt.Println(ColorYellow + "[!] " + msg + ColorReset) }
func logError(msg string)   { fmt.Println(ColorRed + "[✘] " + msg + ColorReset) }

func showUsage() {
	fmt.Println(ColorCyan + "Usage:" + ColorReset)
	fmt.Println("  hide   [--wipe] <secret_file_or_dir> <carrier_file> <output_name>")
	fmt.Println("  reveal <vault_file> <output_name>")
	fmt.Println()
	fmt.Println(ColorYellow + "Notes:" + ColorReset)
	fmt.Println("  • Passwords are entered securely (hidden, no echo)")
	fmt.Println("  • hide: output extension auto-matches the carrier file")
	fmt.Println("  • hide: --wipe enables auto-wipe after 3 failed reveal attempts")
	fmt.Println("  • hide: optionally add a decoy password for plausible deniability")
	fmt.Println("  • reveal: output extension auto-matches the original secret file")
	fmt.Println("  • Output is auto-renamed if it already exists  e.g. file (1).jpg")
}

func readPassword(prompt string) (string, error) {
	fmt.Print(ColorYellow + prompt + ColorReset)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text()), nil
	}
	return "", errors.New("no password provided")
}

func secureWipe(filename string) error {
	info, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("stat %q: %w", filename, err)
	}
	size := info.Size()
	buf := make([]byte, bufferSize)

	for pass := 0; pass < 3; pass++ {
		f, err := os.OpenFile(filename, os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("open for wipe pass %d: %w", pass+1, err)
		}
		remaining := size
		for remaining > 0 {
			chunk := int64(len(buf))
			if remaining < chunk {
				chunk = remaining
			}
			if _, err := io.ReadFull(rand.Reader, buf[:chunk]); err != nil {
				f.Close()
				return fmt.Errorf("rand read pass %d: %w", pass+1, err)
			}
			if _, err := f.Write(buf[:chunk]); err != nil {
				f.Close()
				return fmt.Errorf("write pass %d: %w", pass+1, err)
			}
			remaining -= chunk
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return fmt.Errorf("sync pass %d: %w", pass+1, err)
		}
		f.Close()
	}
	return os.Remove(filename)
}

//Directory  ZIP

func zipDirectory(srcDir string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			_, err = zw.Create(rel + "/")
			return err
		}
		fw, err := zw.Create(rel)
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(fw, f)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("zip walk: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("zip close: %w", err)
	}
	return buf.Bytes(), nil
}

func unzipToDir(data []byte, destDir string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("zip open: %w", err)
	}
	for _, f := range zr.File {
		target := filepath.Join(destDir, f.Name)
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			out.Close()
			return err
		}
		_, cpErr := io.Copy(out, rc)
		rc.Close()
		out.Close()
		if cpErr != nil {
			return cpErr
		}
	}
	return nil
}

func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

func buildAAD(carrierHash []byte, slot byte) []byte {
	aad := make([]byte, len(carrierHash)+2)
	copy(aad, carrierHash)
	aad[len(carrierHash)] = version
	aad[len(carrierHash)+1] = slot
	return aad
}

func encryptChunked(src []byte, carrierHash []byte, password string, slot byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("gen salt: %w", err)
	}
	nonceBase := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonceBase); err != nil {
		return nil, fmt.Errorf("gen nonce: %w", err)
	}

	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	aad := buildAAD(carrierHash, slot)
	numChunks := uint32(0)
	if len(src) > 0 {
		numChunks = uint32((len(src) + chunkSize - 1) / chunkSize)
	}

	var out bytes.Buffer
	out.Write(salt)
	out.Write(nonceBase)
	binary.Write(&out, binary.LittleEndian, numChunks)

	nonce := make([]byte, 12)
	r := bytes.NewReader(src)
	buf := make([]byte, chunkSize)

	for idx := uint32(0); ; idx++ {
		n, readErr := r.Read(buf)
		if n > 0 {
			copy(nonce, nonceBase)
			nonce[0] ^= byte(idx)
			nonce[1] ^= byte(idx >> 8)
			nonce[2] ^= byte(idx >> 16)
			nonce[3] ^= byte(idx >> 24)

			sealed := gcm.Seal(nil, nonce, buf[:n], aad)
			binary.Write(&out, binary.LittleEndian, uint32(len(sealed)))
			out.Write(sealed)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("read chunk %d: %w", idx, readErr)
		}
	}
	return out.Bytes(), nil
}

func decryptChunked(payload []byte, carrierHash []byte, password string, slot byte) ([]byte, error) {
	const hdrLen = 16 + 12 + 4
	if len(payload) < hdrLen {
		return nil, errors.New("payload too short")
	}

	salt := payload[:16]
	nonceBase := payload[16:28]
	numChunks := binary.LittleEndian.Uint32(payload[28:32])
	pos := 32

	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	aad := buildAAD(carrierHash, slot)
	nonce := make([]byte, 12)
	var plain bytes.Buffer

	for idx := uint32(0); idx < numChunks; idx++ {
		if pos+4 > len(payload) {
			return nil, fmt.Errorf("truncated at chunk %d header", idx)
		}
		sealedLen := int(binary.LittleEndian.Uint32(payload[pos : pos+4]))
		pos += 4
		if pos+sealedLen > len(payload) {
			return nil, fmt.Errorf("truncated at chunk %d data", idx)
		}
		sealed := payload[pos : pos+sealedLen]
		pos += sealedLen

		copy(nonce, nonceBase)
		nonce[0] ^= byte(idx)
		nonce[1] ^= byte(idx >> 8)
		nonce[2] ^= byte(idx >> 16)
		nonce[3] ^= byte(idx >> 24)

		open, err := gcm.Open(nil, nonce, sealed, aad)
		if err != nil {
			return nil, errors.New("decryption failed")
		}
		plain.Write(open)
	}
	return plain.Bytes(), nil
}

func showProgress(label string, total, done int64) {
	const width = 40
	if total == 0 {
		return
	}
	ratio := float64(done) / float64(total)
	filled := int(ratio * float64(width))
	fmt.Printf("\r%-22s [%s%s] %5.1f%%",
		label,
		strings.Repeat("█", filled),
		strings.Repeat("░", width-filled),
		ratio*100,
	)
	if done >= total {
		fmt.Println()
	}
}

func readFileBuf(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", path, err)
	}
	size := info.Size()
	data := make([]byte, 0, size)
	buf := make([]byte, bufferSize)
	var read int64
	br := bufio.NewReaderSize(f, bufferSize)

	for {
		n, err := br.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
			read += int64(n)
			showProgress("Reading", size, read)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read %q: %w", path, err)
		}
	}
	return data, nil
}

func resolveOutputPath(requested string) string {
	if _, err := os.Stat(requested); os.IsNotExist(err) {
		return requested
	}
	ext, base := "", requested
	if dot := strings.LastIndex(requested, "."); dot != -1 {
		ext = requested[dot:]
		base = requested[:dot]
	}
	for n := 1; n <= 9999; n++ {
		candidate := fmt.Sprintf("%s (%d)%s", base, n, ext)
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			logWarn(fmt.Sprintf("File %q exists — saving as %q", requested, candidate))
			return candidate
		}
	}
	rb := make([]byte, 4)
	_, _ = rand.Read(rb)
	return fmt.Sprintf("%s_%x%s", base, rb, ext)
}

func streamWrite(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create %q: %w", path, err)
	}
	defer f.Close()

	w := bufio.NewWriterSize(f, bufferSize)
	total := int64(len(data))
	r := bytes.NewReader(data)
	buf := make([]byte, bufferSize)
	var written int64

	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return fmt.Errorf("write: %w", werr)
			}
			written += int64(n)
			showProgress("Writing", total, written)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush: %w", err)
	}
	return f.Sync()
}

func writeOutput(requested string, data []byte) (string, error) {
	path := resolveOutputPath(requested)
	return path, streamWrite(path, data)
}

func printChecksum(label string, data []byte) {
	h := sha256.Sum256(data)
	logInfo(fmt.Sprintf("%s SHA-256: %x", label, h))
}

const flagWipeOnFail = byte(0x01)

func deriveHMACKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 32*1024, 2, 32)
}

func counterHMAC(key []byte, flags, attemptsLeft byte, carrierHash []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte{flags, attemptsLeft})
	mac.Write(carrierHash)
	return mac.Sum(nil)
}

func buildVault(carrier, real, decoy []byte, flags, attemptsLeft byte, hmacSalt, mac []byte) ([]byte, error) {
	var v bytes.Buffer
	v.Grow(len(carrier) + 7 + hmacSaltLen + hmacLen + 4 + len(real) + 4 + len(decoy))
	v.Write(carrier)
	v.WriteString(magic)
	v.WriteByte(version)
	v.WriteByte(flags)
	v.WriteByte(attemptsLeft)
	v.Write(hmacSalt) // 16 bytes
	v.Write(mac)      // 32 bytes
	binary.Write(&v, binary.BigEndian, uint32(len(real)))
	v.Write(real)
	binary.Write(&v, binary.BigEndian, uint32(len(decoy)))
	v.Write(decoy)
	return v.Bytes(), nil
}

func parseVault(data []byte) (carrier, realSlot, decoySlot []byte, flags, attemptsLeft byte, attemptsOffset int, hmacSalt, storedMAC []byte, err error) {
	needle := []byte(magic)
	mIdx := -1
	for i := len(data) - len(needle); i >= 0; i-- {
		if bytes.Equal(data[i:i+len(needle)], needle) && len(data) >= i+63 {
			mIdx = i
			break
		}
	}
	if mIdx == -1 {
		return nil, nil, nil, 0, 0, 0, nil, nil, errors.New("magic marker not found — not a valid vault")
	}

	pos := mIdx + 4
	if data[pos] != version {
		return nil, nil, nil, 0, 0, 0, nil, nil, fmt.Errorf("unsupported vault version %d (need %d)", data[pos], version)
	}
	pos++
	flags = data[pos]
	pos++

	pos++

	pos += hmacSaltLen + hmacLen

	readSlot := func() ([]byte, error) {
		if pos+4 > len(data) {
			return nil, errors.New("truncated slot length")
		}
		n := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if pos+n > len(data) {
			return nil, errors.New("truncated slot data")
		}
		s := data[pos : pos+n]
		pos += n
		return s, nil
	}

	if realSlot, err = readSlot(); err != nil {
		return nil, nil, nil, 0, 0, 0, nil, nil, err
	}
	if decoySlot, err = readSlot(); err != nil {
		return nil, nil, nil, 0, 0, 0, nil, nil, err
	}
	carrier = data[:mIdx]

	attemptsOffset = mIdx + 4 + 1 + 1
	attemptsLeft = data[attemptsOffset]
	hmacSalt = data[attemptsOffset+1 : attemptsOffset+1+hmacSaltLen]
	storedMAC = data[attemptsOffset+1+hmacSaltLen : attemptsOffset+1+hmacSaltLen+hmacLen]
	return
}

func restoreSecret(plain []byte, outBase string) error {

	if len(plain) < 1 {
		return errors.New("empty payload")
	}
	extLen := int(plain[0])
	if extLen > 20 || len(plain) < 1+extLen {

		logWarn(fmt.Sprintf("Metadata invalid (extLen=%d) — restoring as-is", extLen))
		actualPath, err := writeOutput(outBase, plain)
		if err != nil {
			return err
		}
		logSuccess(fmt.Sprintf("File restored: %q", actualPath))
		return nil
	}
	origExt := strings.TrimSpace(string(plain[1 : 1+extLen]))
	content := plain[1+extLen:]

	if len(content) == 0 {
		return errors.New("restored content is empty")
	}

	outPath := replaceExt(outBase, origExt)
	logInfo(fmt.Sprintf("Restoring as: %q  (ext=%q, size=%d bytes)", outPath, origExt, len(content)))

	if origExt == ".zip" {

		outDir := resolveOutputPath(strings.TrimSuffix(outBase, filepath.Ext(outBase)))
		logInfo(fmt.Sprintf("Extracting directory to: %q", outDir))
		if err := os.MkdirAll(outDir, 0700); err != nil {
			return fmt.Errorf("mkdir %q: %w", outDir, err)
		}
		if err := unzipToDir(content, outDir); err != nil {
			return fmt.Errorf("unzip failed: %w", err)
		}
		printChecksum("Restored", content)
		logSuccess(fmt.Sprintf("Directory restored: %q", outDir))
		return nil
	}

	actualPath, err := writeOutput(outPath, content)
	if err != nil {
		return err
	}
	printChecksum("Restored", content)
	logSuccess(fmt.Sprintf("File restored: %q  (%d bytes)", actualPath, len(content)))
	return nil
}

func extOf(path string) string {

	path = strings.TrimSpace(path)
	return filepath.Ext(path)
}

func replaceExt(base, newExt string) string {
	old := extOf(base)
	if old == "" {
		return base + newExt
	}
	return base[:len(base)-len(old)] + newExt
}

func cmdHide(args []string) {

	wipeOnFail := false
	for i, a := range args {
		if a == "--wipe" {
			wipeOnFail = true
			args = append(args[:i], args[i+1:]...)
			break
		}
	}

	if len(args) < 3 {
		showUsage()
		return
	}
	sec, car, outBase := args[0], args[1], args[2]

	carrierExt := extOf(car)
	outName := replaceExt(outBase, carrierExt)
	if outName != outBase {
		logInfo(fmt.Sprintf("Output filename: %q (extension matched to carrier)", outName))
	}

	info, err := os.Stat(sec)
	if err != nil {
		logError("Secret not found: " + err.Error())
		return
	}

	var secretData []byte
	if info.IsDir() {
		logInfo("Directory detected — zipping...")
		secretData, err = zipDirectory(sec)
		if err != nil {
			logError("Zip failed: " + err.Error())
			return
		}
		logInfo(fmt.Sprintf("Zipped → %d bytes", len(secretData)))
	} else {
		logInfo("Reading secret file...")
		secretData, err = readFileBuf(sec)
		if err != nil {
			logError("Read failed: " + err.Error())
			return
		}
	}
	printChecksum("Secret", secretData)

	secExt := ""
	if info.IsDir() {
		secExt = ".zip"
	} else {

		rawExt := filepath.Ext(filepath.Base(strings.TrimSpace(sec)))
		for _, c := range rawExt {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '.' {
				secExt += string(c)
			}
		}
		if len(secExt) > 10 {
			secExt = secExt[:10]
		}
	}
	logInfo(fmt.Sprintf("Storing secret extension: %q", secExt))

	if len(secExt) > 0 && secExt[0] != '.' {
		secExt = ""
	}
	extBytes := []byte(secExt)
	metaData := make([]byte, 1+len(extBytes)+len(secretData))
	metaData[0] = byte(len(extBytes))
	copy(metaData[1:], extBytes)
	copy(metaData[1+len(extBytes):], secretData)
	secretData = metaData

	logInfo("Reading carrier file...")
	cData, err := readFileBuf(car)
	if err != nil {
		logError("Carrier read failed: " + err.Error())
		return
	}
	carrierHash := sha256.Sum256(cData)

	realPass, err := readPassword("Real password: ")
	if err != nil || realPass == "" {
		logError("Password required.")
		return
	}
	realPass2, err := readPassword("Confirm real password: ")
	if err != nil {
		logError(err.Error())
		return
	}
	if realPass != realPass2 {
		logError("Passwords do not match.")
		return
	}

	logInfo("Deriving key with Argon2id (this takes a moment)...")
	realEncrypted, err := encryptChunked(secretData, carrierHash[:], realPass, slotReal)
	if err != nil {
		logError("Encryption failed: " + err.Error())
		return
	}
	logSuccess("Real slot encrypted.")

	sc := bufio.NewScanner(os.Stdin)
	if !wipeOnFail {
		fmt.Print(ColorYellow + "[?] Auto-wipe vault after 3 failed password attempts? (y/n): " + ColorReset)
		sc.Scan()
		if strings.ToLower(strings.TrimSpace(sc.Text())) == "y" {
			wipeOnFail = true
			logInfo("Auto-wipe enabled — vault will be destroyed after 3 failed attempts.")
		} else {
			logInfo("Auto-wipe disabled — vault will remain after failed attempts.")
		}
	} else {
		logInfo("Auto-wipe enabled (--wipe flag).")
	}

	fmt.Print(ColorYellow + "[?] Add a decoy password? (y/n): " + ColorReset)
	sc.Scan()
	var decoyEncrypted []byte

	if strings.ToLower(strings.TrimSpace(sc.Text())) == "y" {
		decoyPass, err := readPassword("Decoy password: ")
		if err != nil || decoyPass == "" {
			logError("Decoy password required.")
			return
		}
		if decoyPass == realPass {
			logError("Decoy password must differ from the real one.")
			return
		}
		decoyPass2, err := readPassword("Confirm decoy password: ")
		if err != nil {
			logError(err.Error())
			return
		}
		if decoyPass != decoyPass2 {
			logError("Decoy passwords do not match.")
			return
		}

		var decoyContent []byte
		var decoyExt string
		for {
			fmt.Print(ColorYellow + "    Decoy file/dir path (required): " + ColorReset)
			sc.Scan()
			decoyPath := strings.TrimSpace(sc.Text())

			if decoyPath == "" {
				logWarn("A decoy file is required for plausible deniability. Please enter a path.")
				continue
			}
			dInfo, err := os.Stat(decoyPath)
			if err != nil {
				logWarn("Path not found: " + err.Error() + " — try again.")
				continue
			}
			if dInfo.IsDir() {
				decoyContent, err = zipDirectory(decoyPath)
				decoyExt = ".zip"
			} else {
				decoyContent, err = readFileBuf(decoyPath)

				rawExt := filepath.Ext(filepath.Base(decoyPath))
				decoyExt = ""
				for _, c := range rawExt {
					if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
						(c >= '0' && c <= '9') || c == '.' {
						decoyExt += string(c)
					}
				}
				if len(decoyExt) > 10 {
					decoyExt = decoyExt[:10]
				}
				if len(decoyExt) == 0 || decoyExt[0] != '.' {
					decoyExt = ""
				}
			}
			if err != nil {
				logWarn("Read failed: " + err.Error() + " — try again.")
				continue
			}
			break
		}
		logInfo(fmt.Sprintf("Storing decoy extension: %q", decoyExt))

		decoyExtBytes := []byte(decoyExt)
		decoyMeta := make([]byte, 1+len(decoyExtBytes)+len(decoyContent))
		decoyMeta[0] = byte(len(decoyExtBytes))
		copy(decoyMeta[1:], decoyExtBytes)
		copy(decoyMeta[1+len(decoyExtBytes):], decoyContent)
		decoyContent = decoyMeta

		logInfo("Encrypting decoy slot...")
		decoyEncrypted, err = encryptChunked(decoyContent, carrierHash[:], decoyPass, slotDecoy)
		if err != nil {
			logError("Decoy encryption failed: " + err.Error())
			return
		}
		logSuccess("Decoy slot encrypted.")
	} else {

		noise := make([]byte, 256+len(secretData)/8)
		io.ReadFull(rand.Reader, noise)
		dummyExt := []byte(".bin")
		dummyMeta := make([]byte, 1+len(dummyExt)+len(noise))
		dummyMeta[0] = byte(len(dummyExt))
		copy(dummyMeta[1:], dummyExt)
		copy(dummyMeta[1+len(dummyExt):], noise)
		decoyEncrypted, _ = encryptChunked(dummyMeta, carrierHash[:], "", slotDecoy)
		if decoyEncrypted == nil {
			decoyEncrypted = dummyMeta
		}
	}

	logInfo("Building vault...")
	var vaultFlags byte
	if wipeOnFail {
		vaultFlags |= flagWipeOnFail
	}

	hmacSalt := make([]byte, hmacSaltLen)
	if _, err := io.ReadFull(rand.Reader, hmacSalt); err != nil {
		logError("Failed to generate HMAC salt: " + err.Error())
		return
	}
	carrierHash2 := sha256.Sum256(cData)
	hmacKey := deriveHMACKey(realPass, hmacSalt)
	initMAC := counterHMAC(hmacKey, vaultFlags, maxAttempts, carrierHash2[:])

	vaultData, err := buildVault(cData, realEncrypted, decoyEncrypted, vaultFlags, maxAttempts, hmacSalt, initMAC)
	if err != nil {
		logError("Vault build failed: " + err.Error())
		return
	}

	logInfo("Writing vault file...")
	actualPath, err := writeOutput(outName, vaultData)
	if err != nil {
		logError(err.Error())
		return
	}
	logSuccess(fmt.Sprintf("Vault created: %q  (%d bytes)", actualPath, len(vaultData)))
}

func cmdReveal(args []string) {
	if len(args) < 2 {
		showUsage()
		return
	}
	car, out := args[0], args[1]

	logInfo("Reading vault file...")
	data, err := readFileBuf(car)
	if err != nil {
		logError("Read failed: " + err.Error())
		return
	}

	carrier, realSlot, decoySlot, vaultFlags, attemptsLeft, attemptsOffset, hmacSalt, storedMAC, err := parseVault(data)
	if err != nil {
		logError(err.Error())
		return
	}
	carrierHash := sha256.Sum256(carrier)
	wipeOnFail := vaultFlags&flagWipeOnFail != 0

	if attemptsLeft == 0 {
		if wipeOnFail {
			logError("No attempts remaining. Securely wiping vault...")
			secureWipe(car)
			return
		}

		attemptsLeft = byte(maxAttempts)
	}

	if wipeOnFail {
		logInfo(fmt.Sprintf("%d attempt(s) remaining.", attemptsLeft))
	}

	pass, err := readPassword("Password: ")
	if err != nil {
		logError(err.Error())
		return
	}

	hmacKey := deriveHMACKey(pass, hmacSalt)
	_ = storedMAC

	if plain, err := decryptChunked(realSlot, carrierHash[:], pass, slotReal); err == nil {

		newMAC := counterHMAC(hmacKey, vaultFlags, maxAttempts, carrierHash[:])
		patchAttempts(car, data, attemptsOffset, maxAttempts, newMAC)
		if err := restoreSecret(plain, out); err != nil {
			logError(err.Error())
		}
		return
	}

	if plain, err := decryptChunked(decoySlot, carrierHash[:], pass, slotDecoy); err == nil {
		newMAC := counterHMAC(hmacKey, vaultFlags, maxAttempts, carrierHash[:])
		patchAttempts(car, data, attemptsOffset, maxAttempts, newMAC)
		if err := restoreSecret(plain, out); err != nil {
			logError(err.Error())
		}
		return
	}

	logWarn("Access denied.")

	if wipeOnFail {

		attemptsLeft--
		sentinelMAC := counterHMAC(hmacKey, vaultFlags, attemptsLeft, carrierHash[:])
		patchAttempts(car, data, attemptsOffset, attemptsLeft, sentinelMAC)

		if attemptsLeft == 0 {
			logError("No attempts remaining. Securely wiping vault...")
			if err := secureWipe(car); err != nil {
				logError("Wipe failed: " + err.Error())
			} else {
				logSuccess("Vault wiped permanently.")
			}
		} else {
			logWarn(fmt.Sprintf("%d attempt(s) remaining.", attemptsLeft))
		}
	}

}

func patchAttempts(vaultPath string, vaultData []byte, offset int, val byte, newMAC []byte) {
	f, err := os.OpenFile(vaultPath, os.O_WRONLY, 0600)
	if err != nil {
		logWarn("Could not persist attempt counter: " + err.Error())
		return
	}
	defer f.Close()

	if _, err := f.WriteAt([]byte{val}, int64(offset)); err != nil {
		logWarn("Could not write attempt counter: " + err.Error())
		return
	}

	hmacOffset := int64(offset) + 1 + int64(hmacSaltLen)
	if _, err := f.WriteAt(newMAC, hmacOffset); err != nil {
		logWarn("Could not write HMAC: " + err.Error())
	}
	_ = f.Sync()
	_ = vaultData
}

func main() {
	fmt.Println(ColorBlue + "#########################################")
	fmt.Println("#      " + ColorYellow + "   Kitsune & JOURIFT " + ColorReset + ColorBlue + "            #")
	fmt.Println("#      " + ColorYellow + "        PHANTOM      " + ColorReset + ColorBlue + "            #")
	fmt.Println("#    " + ColorCyan + "Zero-Knowledge Shadow Vault" + ColorBlue + "        #")
	fmt.Println("#########################################\n" + ColorReset)

	if len(os.Args) < 2 {
		showUsage()
		return
	}

	cleanArgs := make([]string, len(os.Args))
	for i, a := range os.Args {
		cleanArgs[i] = strings.TrimSpace(a)
	}

	switch cleanArgs[1] {
	case "hide":
		cmdHide(cleanArgs[2:])
	case "reveal":
		cmdReveal(cleanArgs[2:])
	default:
		logError("Unknown command: " + cleanArgs[1])
		fmt.Println()
		showUsage()
	}
}
