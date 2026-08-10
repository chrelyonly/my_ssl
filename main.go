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
	"embed"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

// 内存中缓存的内置/本地 CA 结构
type InternalCA struct {
	Cert    *x509.Certificate
	Key     crypto.Signer
	CertPEM string
	KeyPEM  string
}

var presetCAMap = make(map[string]*InternalCA)

//go:embed public/*
var staticFS embed.FS

func main() {
	initPresetCAsFromTemplate()

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.Use(corsMiddleware())

	// ===== 路由配置 =====
	r.POST("/generate", handleGenerateCerts)

	// ===== 静态资源与 SPA 路由适配 =====
	subFS, err := fs.Sub(staticFS, "public")
	if err != nil {
		panic(fmt.Sprintf("初始化嵌入文件失败: %v", err))
	}

	httpFS := http.FS(subFS)

	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path

		if strings.HasPrefix(path, "/generate") {
			return
		}

		// 检查静态资源是否存在
		f, err := subFS.Open(strings.TrimPrefix(path, "/"))
		if err == nil {
			_ = f.Close()
			http.FileServer(httpFS).ServeHTTP(c.Writer, c.Request)
			return
		}

		// SPA 路由回退至 index.html
		c.Request.URL.Path = "/"
		http.FileServer(httpFS).ServeHTTP(c.Writer, c.Request)
	})

	fmt.Println("🚀 PKI 证书签发后端已启动于 :8080...")
	if err := r.Run(":8080"); err != nil {
		fmt.Printf("❌ 服务启动失败: %v\n", err)
	}
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
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("选中的预设 CA (%s) 未找到，请检查 template/%s 目录", req.PresetID, req.PresetID)})
			return
		}
		caCert = preset.Cert
		caKey = preset.Key
		caCertPEM = preset.CertPEM
		caKeyPEM = preset.KeyPEM
	} else {
		caCert, caKey, caCertPEM, caKeyPEM, err = generateCustomCA(req.CA, req.KeySpec)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "自定义 CA 生成失败: " + err.Error()})
			return
		}
	}

	// Step 2: 生成服务端私钥与证书
	serverCertPEM, serverKeyPEM, err := generateServerCert(caCert, caKey, req.Domains, req.IPs, req.KeySpec)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务端证书签发失败: " + err.Error()})
		return
	}

	// Step 3: 打包 ZIP
	zipBuf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(zipBuf)

	if req.Targets.CACert && caCertPEM != "" {
		if err := addFileToZip(zipWriter, "ca.pem", []byte(caCertPEM)); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "打包 ca.pem 失败: " + err.Error()})
			return
		}
	}
	if req.Targets.CAKey && caKeyPEM != "" {
		if err := addFileToZip(zipWriter, "ca.key", []byte(caKeyPEM)); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "打包 ca.key 失败: " + err.Error()})
			return
		}
	}
	if req.Targets.ServerCert && serverCertPEM != "" {
		if err := addFileToZip(zipWriter, "server.pem", []byte(serverCertPEM)); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "打包 server.pem 失败: " + err.Error()})
			return
		}
	}
	if req.Targets.ServerKey && serverKeyPEM != "" {
		if err := addFileToZip(zipWriter, "server.key", []byte(serverKeyPEM)); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "打包 server.key 失败: " + err.Error()})
			return
		}
	}

	if err := zipWriter.Close(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "关闭 ZIP 写入流失败: " + err.Error()})
		return
	}

	// Step 4: 返回二进制流下载
	c.Header("Content-Disposition", "attachment; filename=certs.zip")
	c.Header("Content-Type", "application/zip")
	c.Data(http.StatusOK, "application/zip", zipBuf.Bytes())
}

// ===== 本地 template 目录 CA 证书加载 =====

func initPresetCAsFromTemplate() {
	presets := []struct {
		id   string
		name string
	}{
		{id: "1", name: "chrelyonly专用证书"},
		{id: "2", name: "访客通用证书"},
	}

	// 🛠️ 优化：优先获取可执行文件真实路径，避免 cd 到其他目录运行时读取失败
	baseDir := "."
	if execPath, err := os.Executable(); err == nil {
		baseDir = filepath.Dir(execPath)
	}

	for _, p := range presets {
		targetDir := filepath.Join(baseDir, "template", p.id)
		certPath := findCertFile(targetDir)
		keyPath := filepath.Join(targetDir, "ca.key")

		if certPath == "" {
			fmt.Printf("⚠️ 警告: 预设 CA [%s - %s] 未找到证书文件 (%s/ca.pem)\n", p.id, p.name, targetDir)
			continue
		}

		ca, err := loadCAFromDisk(certPath, keyPath)
		if err != nil {
			fmt.Printf("⚠️ 警告: 无法加载预设 CA [%s - %s]: %v\n", p.id, p.name, err)
			continue
		}

		presetCAMap[p.id] = ca
		fmt.Printf("✅ 成功加载预设 CA [%s - %s]\n", p.id, p.name)
	}
}

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
		return nil, fmt.Errorf("证书 PEM 格式无效")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析 x509 证书失败: %w", err)
	}

	// 解析私钥
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return nil, fmt.Errorf("私钥 PEM 格式无效")
	}

	var key crypto.Signer
	if parsedKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
		key = parsedKey
	} else if parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
		key = parsedKey.(crypto.Signer)
	} else if parsedKey, err := x509.ParseECPrivateKey(keyBlock.Bytes); err == nil {
		key = parsedKey
	} else {
		return nil, fmt.Errorf("不支持或无法解析的私钥格式")
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
	switch strings.ToUpper(spec.Type) {
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

	// 🛠️ 修复：安全生成 SerialNumber，防止 nil 指针崩溃
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("生成证书序列号失败: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{info.Country},
			Province:           []string{info.Province},
			Organization:       []string{info.Organization},
			OrganizationalUnit: []string{info.OrganizationalUnit},
			CommonName:         info.CommonName,
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

	// 🛠️ 修复：安全生成 SerialNumber
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", "", fmt.Errorf("生成证书序列号失败: %w", err)
	}

	// 🛠️ 优化 KeyUsage：仅针对 RSA 添加 KeyEncipherment
	keyUsage := x509.KeyUsageDigitalSignature
	if strings.ToUpper(spec.Type) == "RSA" {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().AddDate(1, 0, 0), // 遵从 Modern TLS 标准，限制 1 年有效期
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	dnsMap := make(map[string]bool)
	ipMap := make(map[string]bool)

	// 解析与清洗 domains
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		if ip := net.ParseIP(domain); ip != nil {
			if !ipMap[ip.String()] {
				template.IPAddresses = append(template.IPAddresses, ip)
				ipMap[ip.String()] = true
			}
			continue
		}
		asciiDomain, err := idna.ToASCII(domain)
		if err != nil {
			asciiDomain = domain
		}
		if !dnsMap[asciiDomain] {
			template.DNSNames = append(template.DNSNames, asciiDomain)
			dnsMap[asciiDomain] = true
		}
	}

	// 解析与清洗 ips
	for _, ipStr := range ips {
		ipStr = strings.TrimSpace(ipStr)
		if ip := net.ParseIP(ipStr); ip != nil {
			if !ipMap[ip.String()] {
				template.IPAddresses = append(template.IPAddresses, ip)
				ipMap[ip.String()] = true
			}
		}
	}

	// 🛠️ 自动设置合规的 CommonName
	if len(template.DNSNames) > 0 {
		template.Subject.CommonName = template.DNSNames[0]
	} else if len(template.IPAddresses) > 0 {
		template.Subject.CommonName = template.IPAddresses[0].String()
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, key.Public(), caKey)
	if err != nil {
		return "", "", err
	}

	certPEM := encodeToPEM("CERTIFICATE", certBytes)
	keyPEM, err := encodePrivateKeyToPEM(key)

	return certPEM, keyPEM, err
}

// ===== 工具函数 =====

func encodeToPEM(blockType string, rawData []byte) string {
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: blockType, Bytes: rawData})
	return buf.String()
}

func encodePrivateKeyToPEM(key crypto.Signer) (string, error) {
	rawBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return encodeToPEM("PRIVATE KEY", rawBytes), nil
}

func addFileToZip(zw *zip.Writer, filename string, content []byte) error {
	f, err := zw.Create(filename)
	if err != nil {
		return err
	}
	_, err = f.Write(content)
	return err
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, Authorization")
		// 🛠️ 关键补充：允许前端读取 Content-Disposition 响应头以获取文件名
		c.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Disposition")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
