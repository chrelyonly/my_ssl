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
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/net/idna"
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
	PresetID string   `json:"presetId"` // 预设 CA ID: "1" 或 "2" 等
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

// 内存中缓存的内置/本地 CA 结构
type InternalCA struct {
	Cert    *x509.Certificate
	Key     crypto.Signer
	CertPEM string
	KeyPEM  string
}

var presetCAMap = make(map[string]*InternalCA)

// ===== 主入口函数 =====

func main() {
	// 初始化从 template/{id}/ 目录加载预设 CA 证书
	initPresetCAsFromTemplate()

	r := gin.Default()

	// 跨域中间件
	r.Use(corsMiddleware())

	// 1. 获取预设 CA 列表接口
	r.GET("/api/presets", func(c *gin.Context) {
		presets := []PresetCA{
			{ID: "1", Name: "chrelyonly专用证书"},
			{ID: "2", Name: "访客通用证书"},
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
		if !ok || preset == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("选中的预设 CA (%s) 未找到或未成功加载 template/%s 目录下的证书", req.PresetID, req.PresetID)})
			return
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

	// Step 2: 生成服务端私钥与证书（使用选定的 CA 进行签发）
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

// ===== 本地 template 目录 CA 证书文件读取加载 =====

func initPresetCAsFromTemplate() {
	presets := []struct {
		id   string
		name string
	}{
		{id: "1", name: "chrelyonly专用证书"},
		{id: "2", name: "访客通用证书"},
	}

	execDir, err := os.Getwd()
	if err != nil {
		execDir = "."
	}

	for _, p := range presets {
		// 读取路径类似: template/1/ca.pem 和 template/1/ca.key
		targetDir := filepath.Join(execDir, "template", p.id)

		certPath := findCertFile(targetDir)
		keyPath := filepath.Join(targetDir, "ca.key")

		if certPath == "" {
			fmt.Printf("⚠️ 警告: 预设 CA [%s - %s] 未能找到证书文件 (%s/ca.pem)\n", p.id, p.name, targetDir)
			continue
		}

		ca, err := loadCAFromDisk(certPath, keyPath)
		if err != nil {
			fmt.Printf("⚠️ 警告: 无法加载预设 CA [%s - %s]: %v\n", p.id, p.name, err)
			continue
		}

		presetCAMap[p.id] = ca
		fmt.Printf("✅ 成功从 [%s] 加载预设 CA [%s - %s]\n", certPath, p.id, p.name)
	}
}

// 寻找 template/{id} 目录下可能存在的证书文件名 (ca.pem / ca.crt / ca.cer)
func findCertFile(dir string) string {
	candidates := []string{"ca.pem", "ca.crt", "ca.cer"}
	for _, name := range candidates {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// 从磁盘读取并解析 PEM 格式的证书和私钥
func loadCAFromDisk(certPath, keyPath string) (*InternalCA, error) {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("读取证书文件失败: %w", err)
	}

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("读取私钥文件失败: %w", err)
	}

	// 解析证书
	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		return nil, fmt.Errorf("证书 PEM 解析失败")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析 x509 证书失败: %w", err)
	}

	// 解析私钥 (支持 PKCS1, PKCS8, EC)
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return nil, fmt.Errorf("私钥 PEM 解析失败")
	}

	var key crypto.Signer
	if parsedKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
		key = parsedKey
	} else if parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
		key = parsedKey.(crypto.Signer)
	} else if parsedKey, err := x509.ParseECPrivateKey(keyBlock.Bytes); err == nil {
		key = parsedKey
	} else {
		return nil, fmt.Errorf("不支持的私钥格式")
	}

	return &InternalCA{
		Cert:    cert,
		Key:     key,
		CertPEM: string(certBytes),
		KeyPEM:  string(keyBytes),
	}, nil
}

// ===== PKI 密钥与证书生成辅助函数 =====

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

func generateServerCert(caCert *x509.Certificate, caKey crypto.Signer, domains []string, ips []string, spec KeySpec) (string, string, error) {
	key, err := generatePrivateKey(spec)
	if err != nil {
		return "", "", err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// 转换 CommonName 为 ASCII/Punycode（如果包含了中文）
	commonName := "localhost"
	if len(domains) > 0 && domains[0] != "" {
		asciiCN, err := idna.ToASCII(domains[0])
		if err == nil {
			commonName = asciiCN
		} else {
			commonName = domains[0]
		}
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// 处理 SAN 域名与 IP
	for _, domain := range domains {
		if domain == "" {
			continue
		}

		// 1. 尝试解析为 IP
		if ip := net.ParseIP(domain); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
			continue
		}

		// 2. 将中文域名转为 Punycode ASCII 格式
		asciiDomain, err := idna.ToASCII(domain)
		if err != nil {
			// 如果转码失败，仍保留原域名尝试处理
			asciiDomain = domain
		}

		template.DNSNames = append(template.DNSNames, asciiDomain)
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
