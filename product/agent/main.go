// The ADA native client enrolls and reports observe-only heartbeats over HTTPS.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const build = "0.1.0"

var (
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	keyPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type credential struct {
	Origin string `json:"origin"`
	Tenant string `json:"tenant"`
	Device string `json:"device"`
	Token  string `json:"credential"`
}

type client struct {
	origin, tenant string
	http           *http.Client
}

func newClient(endpoint, tenant, caFile string) (client, error) {
	origin, err := url.Parse(endpoint)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil ||
		origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" ||
		(origin.Path != "" && origin.Path != "/") || !uuidPattern.MatchString(tenant) {
		return client{}, errors.New("expected an HTTPS origin and a canonical tenant UUID")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return client{}, fmt.Errorf("read trusted CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return client{}, errors.New("invalid trusted CA")
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	return client{
		origin: strings.TrimSuffix(origin.String(), "/"),
		tenant: tenant,
		http: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c client) post(ctx context.Context, operation, token string, data any, result any) (int, error) {
	body, err := json.Marshal(data)
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, c.origin+"/v1/tenants/"+c.tenant+"/"+operation, bytes.NewReader(body),
	)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusCreated && result != nil {
		err = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(result)
	} else {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	}
	return response.StatusCode, err
}

func (c client) enroll(ctx context.Context, file, grant string) error {
	if !keyPattern.MatchString(grant) {
		return errors.New("enrollment requires ADA_ENROLLMENT_GRANT")
	}
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(file+".lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	lock.Close()
	defer os.Remove(lock.Name())
	if _, err := os.Lstat(file); !errors.Is(err, os.ErrNotExist) {
		return errors.New("credential file already exists or cannot be checked")
	}

	var issued struct {
		Device, Credential, Mode string
	}
	status, err := c.post(ctx, "enroll", grant, map[string]string{
		"platform": runtime.GOOS, "arch": runtime.GOARCH,
	}, &issued)
	if err != nil {
		return fmt.Errorf("enrollment request: %w", err)
	}
	if status != http.StatusCreated || issued.Mode != "observe-only" ||
		!uuidPattern.MatchString(issued.Device) || !keyPattern.MatchString(issued.Credential) {
		return fmt.Errorf("enrollment rejected or invalid response (HTTP %d)", status)
	}
	encoded, err := json.Marshal(credential{c.origin, c.tenant, issued.Device, issued.Credential})
	if err != nil {
		return err
	}
	staging, err := os.CreateTemp(filepath.Dir(file), ".credential-*")
	if err != nil {
		return err
	}
	defer os.Remove(staging.Name())
	if _, err = staging.Write(encoded); err == nil {
		err = staging.Sync()
	}
	if closeErr := staging.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(staging.Name(), file); err != nil {
		return err
	}
	log.Printf("enrolled device %s in observe-only mode", issued.Device)
	return nil
}

func (c client) load(file string) (credential, error) {
	var state credential
	stream, err := os.Open(file)
	if err != nil {
		return state, err
	}
	defer stream.Close()
	info, err := stream.Stat()
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return state, errors.New("credential file must be private and regular")
	}
	if err := json.NewDecoder(io.LimitReader(stream, 4096)).Decode(&state); err != nil {
		return state, errors.New("invalid credential record")
	}
	if state.Origin != c.origin || state.Tenant != c.tenant ||
		!uuidPattern.MatchString(state.Device) || !keyPattern.MatchString(state.Token) {
		return state, errors.New("credential scope does not match the configured endpoint")
	}
	return state, nil
}

func (c client) report(ctx context.Context, state credential, interval time.Duration, once bool) error {
	for {
		// Generate a version 4 UUID from operating-system randomness.
		var data [16]byte
		rand.Read(data[:])
		data[6] = (data[6] & 0x0f) | 0x40
		data[8] = (data[8] & 0x3f) | 0x80
		id := fmt.Sprintf("%x-%x-%x-%x-%x", data[:4], data[4:6], data[6:8], data[8:10], data[10:])
		for {
			status, err := c.post(ctx, "events", state.Token, map[string]string{"id": id, "build": build}, nil)
			if err == nil && status == http.StatusAccepted {
				break
			}
			if ctx.Err() != nil {
				return nil
			}
			if err == nil && status >= 400 && status < 500 && status != 429 {
				return fmt.Errorf("heartbeat rejected (HTTP %d)", status)
			}
			if once {
				return fmt.Errorf("heartbeat unavailable (HTTP %d)", status)
			}
			log.Print("heartbeat unavailable, retrying with the same event ID")
			if !pause(ctx, interval) {
				return nil
			}
		}
		if once || !pause(ctx, interval) {
			return nil
		}
	}
}

func pause(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func run() error {
	endpoint := flag.String("url", "", "HTTPS control-plane origin")
	tenant := flag.String("tenant", "", "tenant UUID")
	ca := flag.String("ca", "", "optional PEM CA bundle")
	state := flag.String("state", "", "private credential file")
	enroll := flag.Bool("enroll", false, "consume a grant and enroll the agent")
	once := flag.Bool("once", false, "report a single heartbeat and exit")
	interval := flag.Duration("interval", time.Minute, "heartbeat interval")
	version := flag.Bool("version", false, "print build and platform")
	flag.Parse()
	if *version {
		fmt.Printf("ada-agent %s %s/%s\n", build, runtime.GOOS, runtime.GOARCH)
		return nil
	}
	if *state == "" || *interval < 5*time.Second || (*enroll && *once) {
		return errors.New("a private state path and interval of at least 5s are required")
	}
	c, err := newClient(*endpoint, *tenant, *ca)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	grant := os.Getenv("ADA_ENROLLMENT_GRANT")
	os.Unsetenv("ADA_ENROLLMENT_GRANT")
	if *enroll {
		return c.enroll(ctx, *state, grant)
	}
	identity, err := c.load(*state)
	if err != nil {
		return err
	}
	return c.report(ctx, identity, *interval, *once)
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
