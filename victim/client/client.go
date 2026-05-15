package client

import (
	"bytes"
	crand "crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http"
	"time"

	"victim-app/crypto"
	"victim-app/middleware"
)

// Client that interacts with the server 
type VictimClient struct {
	BaseURL      string
	TargetURL    string
	HTTPClient   *http.Client
	Logger       *middleware.SnifferLogger
	ClientRandom []byte
	ServerRandom []byte
	Keys         *crypto.SessionKeys
}

func NewVictimClient(baseURL, targetURL string, l *middleware.SnifferLogger) *VictimClient {
	cRandom := make([]byte, 32)
	sRandom := make([]byte, 32)
	crand.Read(cRandom)
	crand.Read(sRandom)

	return &VictimClient{
		BaseURL:   baseURL,
		TargetURL: targetURL,
		HTTPClient: &http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
			Timeout:   10 * time.Second,
		},
		Logger:       l,
		ClientRandom: cRandom,
		ServerRandom: sRandom,
	}
}

func (c *VictimClient) RunSimulation() {
	fmt.Println("[VICTIM] Fetching server public key...")
	pubKey, err := crypto.FetchPublicKey(c.TargetURL)
	if err != nil {
		fmt.Printf("[VICTIM] Error fetching public key: %v\n", err)
		return
	}

	// Handshake Logging with Randoms
	c.Logger.LogPacket(c.Logger.VictimAddress, c.Logger.ServerAddress, "Handshake", "ClientHello", fmt.Sprintf("%x", c.ClientRandom))
	c.Logger.LogPacket(c.Logger.ServerAddress, c.Logger.VictimAddress, "Handshake", "ServerHello", fmt.Sprintf("%x", c.ServerRandom))

	pms := make([]byte, 48)
	crand.Read(pms)
	pms[0], pms[1] = 0x03, 0x03 // TLS 1.2 version in PMS

	pmsEnc := crypto.EncryptPKCS1v15(pubKey, pms)
	c.Logger.LogPacket(c.Logger.VictimAddress, c.Logger.ServerAddress, "Handshake", "ClientKeyExchange", fmt.Sprintf("%x", pmsEnc))

	// Key Derivation
	ms := crypto.DeriveMasterSecret(pms, c.ClientRandom, c.ServerRandom)
	c.Keys = crypto.DeriveSessionKeys(ms, c.ClientRandom, c.ServerRandom)

	c.Logger.LogPacket(c.Logger.VictimAddress, c.Logger.ServerAddress, "Handshake", "ChangeCipherSpec", "")

	fmt.Println("[VICTIM] Starting interaction flow...")
	c.Login()
	time.Sleep(1 * time.Second)
	c.ListProducts()
	time.Sleep(1 * time.Second)
	c.ViewRandomProducts()
	c.PlaceOrder()
	fmt.Println("[VICTIM] Flow complete. Silence starting now...")
}

func (c *VictimClient) encryptAndLog(src, dst, plaintext string, key []byte) {
	iv := make([]byte, 16)
	crand.Read(iv)
	ciphertext := crypto.EncryptAESCBC(key, []byte(plaintext), iv)
	c.Logger.LogPacket(src, dst, "AppData", plaintext, fmt.Sprintf("%x", ciphertext))
}

func (c *VictimClient) Login() {
	loginBody := `{"username": "victim_user", "password": "SuperSecretPassword123!"}`
	payload := "POST /auth/login HTTP/1.1\r\n\r\n" + loginBody
	c.encryptAndLog(c.Logger.VictimAddress, c.Logger.ServerAddress, payload, c.Keys.ClientWriteKey)
	
	resp, _ := c.HTTPClient.Post(c.BaseURL+"/auth/login", "application/json", bytes.NewBuffer([]byte(loginBody)))
	if resp != nil {
		body, _ := io.ReadAll(resp.Body)
		c.encryptAndLog(c.Logger.ServerAddress, c.Logger.VictimAddress, "HTTP/1.1 200 OK\r\n\r\n"+string(body), c.Keys.ServerWriteKey)
		resp.Body.Close()
	}
}

func (c *VictimClient) ListProducts() {
	c.encryptAndLog(c.Logger.VictimAddress, c.Logger.ServerAddress, "GET /products/ HTTP/1.1", c.Keys.ClientWriteKey)
	resp, _ := c.HTTPClient.Get(c.BaseURL + "/products/")
	if resp != nil {
		body, _ := io.ReadAll(resp.Body)
		c.encryptAndLog(c.Logger.ServerAddress, c.Logger.VictimAddress, "HTTP/1.1 200 OK\r\n\r\n"+string(body), c.Keys.ServerWriteKey)
		resp.Body.Close()
	}
}

func (c *VictimClient) ViewRandomProducts() {
	mrand.Seed(time.Now().UnixNano())
	iterations := mrand.Intn(2) + 3
	for i := 0; i < iterations; i++ {
		pID := mrand.Intn(3) + 1
		path := fmt.Sprintf("/products/%d", pID)
		c.encryptAndLog(c.Logger.VictimAddress, c.Logger.ServerAddress, "GET "+path+" HTTP/1.1", c.Keys.ClientWriteKey)
		resp, _ := c.HTTPClient.Get(c.BaseURL + path)
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			c.encryptAndLog(c.Logger.ServerAddress, c.Logger.VictimAddress, "HTTP/1.1 200 OK\r\n\r\n"+string(body), c.Keys.ServerWriteKey)
			resp.Body.Close()
		}
		time.Sleep(1 * time.Second)
	}
}

func (c *VictimClient) PlaceOrder() {
	orderBody := `{"item_id": 1, "card": "4111-2222-3333-4444", "cvv": "123"}`
	c.encryptAndLog(c.Logger.VictimAddress, c.Logger.ServerAddress, "POST /orders/ HTTP/1.1\r\n\r\n"+orderBody, c.Keys.ClientWriteKey)
	resp, _ := c.HTTPClient.Post(c.BaseURL+"/orders/", "application/json", bytes.NewBuffer([]byte(orderBody)))
	if resp != nil {
		body, _ := io.ReadAll(resp.Body)
		c.encryptAndLog(c.Logger.ServerAddress, c.Logger.VictimAddress, "HTTP/1.1 200 OK\r\n\r\n"+string(body), c.Keys.ServerWriteKey)
		resp.Body.Close()
	}
}
