package main

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// ===== 请求与响应数据结构定义 =====

type KeySpec struct {
	Type string `json:"type"` // "RSA" | "ECDSA"
	Size int    `json:"size"` // RSA: 2048, 3072, 4096 | ECDSA: 256, 384, 521
}

type Targets struct {
	CACert     bool `json:"caCert"`
	CAKey      bool `json:"caKey"`
	ServerCert bool `json:"serverCert"`
	ServerKey  bool `json:"serverKey"`
}

type CAInfo struct {
	Country            string `json:"country"`
	Province           string `json:"province"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizationalUnit"`
	CommonName         string `json:"commonName"`
	ValidityYears      int    `json:"validityYears"`
}

type GenerateRequest struct {
	CAMode   string   `json:"caMode"`   // "preset" | "custom"
	PresetID string   `json:"presetId"` // 预设 CA ID
	KeySpec  KeySpec  `json:"keySpec"`
	Targets  Targets  `json:"targets"`
	CA       CAInfo   `json:"ca"`
	Domains  []string `json:"domains"`
	IPs      []string `json:"ips"`
}

type PresetCA struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// 内存中缓存的内置 CA 结构
type InternalCA struct {
	Cert    *x509.Certificate
	Key     crypto.Signer
	CertPEM string
	KeyPEM  string
}

var presetCAMap = make(map[string]*InternalCA)

// ===== 主入口函数 =====

func main() {
	// 初始化内置预设 CA
	initPresetCAs()

	r := gin.Default()

	// 跨域中间件
	r.Use(corsMiddleware())

	// 1. 获取内置预设 CA 列表
	r.GET("/api/presets", func(c *gin.Context) {
		presets := []PresetCA{
			{ID: "1", Name: "Internal Default CA (2026)"},
			{ID: "2", Name: "K8s Cluster Root CA"},
		}
		c.JSON(http.StatusOK, presets)
	})

	// 2. 证书生成并打包 Zip 接口
	r.POST("/generate", handleGenerateCerts)

	fmt.Println("🚀 PKI 证书签发后端已启动于 :8080...")
	r.Run(":8080")
}

// ===== 核心业务逻辑实现 =====

func handleGenerateCerts(c *gin.Context) {
	var req GenerateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数解析失败: " + err.Error()})
		return
	}

	var caCert *x509.Certificate
	var caKey crypto.Signer
	var caCertPEM, caKeyPEM string
	var err error

	// Step 1: 获取或生成 CA 根证书
	if req.CAMode == "preset" {
		preset, ok := presetCAMap[req.PresetID]
		if !ok {
			preset = presetCAMap["1"]
		}
		caCert = preset.Cert
		caKey = preset.Key
		caCertPEM = preset.CertPEM
		caKeyPEM = preset.KeyPEM
	} else {
		// 自动生成全新自签名 CA
		caCert, caKey, caCertPEM, caKeyPEM, err = generateCustomCA(req.CA, req.KeySpec)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "自定义 CA 生成失败: " + err.Error()})
			return
		}
	}

	// Step 2: 生成服务端私钥与证书（使用 CA 进行签发）
	serverCertPEM, serverKeyPEM, err := generateServerCert(caCert, caKey, req.Domains, req.IPs, req.KeySpec)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务端证书签发失败: " + err.Error()})
		return
	}

	// Step 3: 根据前端勾选的 Targets 组装 Zip 压缩包
	zipBuf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(zipBuf)

	if req.Targets.CACert && caCertPEM != "" {
		addFileToZip(zipWriter, "ca.pem", []byte(caCertPEM))
	}
	if req.Targets.CAKey && caKeyPEM != "" {
		addFileToZip(zipWriter, "ca.key", []byte(caKeyPEM))
	}
	if req.Targets.ServerCert && serverCertPEM != "" {
		addFileToZip(zipWriter, "server.pem", []byte(serverCertPEM))
	}
	if req.Targets.ServerKey && serverKeyPEM != "" {
		addFileToZip(zipWriter, "server.key", []byte(serverKeyPEM))
	}

	if err := zipWriter.Close(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "打包 ZIP 失败: " + err.Error()})
		return
	}

	// Step 4: 返回文件流供前端下载
	c.Header("Content-Disposition", "attachment; filename=certs.zip")
	c.Header("Content-Type", "application/zip")
	c.Data(http.StatusOK, "application/zip", zipBuf.Bytes())
}

// ===== PKI 密钥与证书生成辅助函数 =====

// 生成密钥对 (RSA / ECDSA)
func generatePrivateKey(spec KeySpec) (crypto.Signer, error) {
	switch spec.Type {
	case "ECDSA":
		var curve elliptic.Curve
		switch spec.Size {
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	case "RSA":
		fallthrough
	default:
		bits := spec.Size
		if bits < 2048 {
			bits = 2048
		}
		return rsa.GenerateKey(rand.Reader, bits)
	}
}

// 生成自定义 CA
func generateCustomCA(info CAInfo, spec KeySpec) (*x509.Certificate, crypto.Signer, string, string, error) {
	key, err := generatePrivateKey(spec)
	if err != nil {
		return nil, nil, "", "", err
	}

	validYears := info.ValidityYears
	if validYears <= 0 {
		validYears = 5
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:      []string{info.Country},
			Organization: []string{info.Organization},
			CommonName:   info.CommonName,
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().AddDate(validYears, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, nil, "", "", err
	}

	parsedCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, "", "", err
	}

	certPEM := encodeToPEM("CERTIFICATE", certBytes)
	keyPEM, err := encodePrivateKeyToPEM(key)

	return parsedCert, key, certPEM, keyPEM, err
}

// 签发服务端证书
func generateServerCert(caCert *x509.Certificate, caKey crypto.Signer, domains []string, ips []string, spec KeySpec) (string, string, error) {
	key, err := generatePrivateKey(spec)
	if err != nil {
		return "", "", err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	commonName := "localhost"
	if len(domains) > 0 && domains[0] != "" {
		commonName = domains[0]
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().AddDate(1, 0, 0), // 服务端证书默认 1 年有效期
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// 处理 SAN (DNS 域名与 IP)
	for _, domain := range domains {
		if domain == "" {
			continue
		}
		if ip := net.ParseIP(domain); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, domain)
		}
	}
	for _, ipStr := range ips {
		if ip := net.ParseIP(ipStr); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, key.Public(), caKey)
	if err != nil {
		return "", "", err
	}

	certPEM := encodeToPEM("CERTIFICATE", certBytes)
	keyPEM, err := encodePrivateKeyToPEM(key)

	return certPEM, keyPEM, err
}

// ===== PEM 格式转换与 Zip 编码工具 =====

func encodeToPEM(blockType string, rawData []byte) string {
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: blockType, Bytes: rawData})
	return buf.String()
}

func encodePrivateKeyToPEM(key crypto.Signer) (string, error) {
	var rawBytes []byte
	var blockType string
	var err error

	switch k := key.(type) {
	case *rsa.PrivateKey:
		rawBytes = x509.MarshalPKCS1PrivateKey(k)
		blockType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		rawBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return "", err
		}
		blockType = "EC PRIVATE KEY"
	default:
		rawBytes, err = x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return "", err
		}
		blockType = "PRIVATE KEY"
	}

	return encodeToPEM(blockType, rawBytes), nil
}

func addFileToZip(zw *zip.Writer, filename string, content []byte) {
	f, err := zw.Create(filename)
	if err != nil {
		return
	}
	f.Write(content)
}

// ===== 预设 CA 初始化 =====

func initPresetCAs() {
	rsaSpec := KeySpec{Type: "RSA", Size: 2048}
	ca1Cert, ca1Key, ca1CertPEM, ca1KeyPEM, _ := generateCustomCA(CAInfo{
		Country:       "CN",
		Organization:  "DevCorp Ops",
		CommonName:    "Internal Default CA (2026)",
		ValidityYears: 10,
	}, rsaSpec)
	presetCAMap["1"] = &InternalCA{Cert: ca1Cert, Key: ca1Key, CertPEM: ca1CertPEM, KeyPEM: ca1KeyPEM}

	ca2Cert, ca2Key, ca2CertPEM, ca2KeyPEM, _ := generateCustomCA(CAInfo{
		Country:       "US",
		Organization:  "Kubernetes Local",
		CommonName:    "K8s Cluster Root CA",
		ValidityYears: 10,
	}, rsaSpec)
	presetCAMap["2"] = &InternalCA{Cert: ca2Cert, Key: ca2Key, CertPEM: ca2CertPEM, KeyPEM: ca2KeyPEM}
}

// CORS 中间件
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}
