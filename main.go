package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	RSABitsSize        = 4096
	CACertFilename     = "build/ca.pem"
	CAKeyFilename      = "build/ca.key"
	ConfigFilename     = "build/config.json"
	ServerCertFilename = "server.pem"
	ServerKeyFilename  = "server.key"
)

// Config 代表 DNS 名称和 IP 地址的配置结构
type Config struct {
	DNSNames    []string `json:"dns_names"`
	IPAddresses []string `json:"ip_addresses"`
}

// 生成 RSA 私钥
func generateRSAKey(bits int) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Fatalf("生成 RSA 私钥失败: %v", err)
	}
	return key
}

// 保存 PEM 文件
func savePEMFile(filename, pemType string, data []byte) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("创建文件 %s 失败: %v", filename, err)
	}
	defer file.Close()
	if err := pem.Encode(file, &pem.Block{Type: pemType, Bytes: data}); err != nil {
		log.Fatalf("写入 PEM 块失败: %v", err)
	}
	log.Printf("%s 保存成功", filename)
}

// 生成并保存证书
func generateCertificate(filename, keyFilename string, template, parent *x509.Certificate, pubKey, parentPrivKey interface{}) {
	certData, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, parentPrivKey)
	if err != nil {
		log.Fatalf("生成证书失败: %v", err)
	}
	savePEMFile(filename, "CERTIFICATE", certData)

	if privKey, ok := parentPrivKey.(*rsa.PrivateKey); ok {
		savePEMFile(keyFilename, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(privKey))
	}
}

// 生成并保存 CA 证书
func generateCACertificate() (*x509.Certificate, *rsa.PrivateKey) {
	caKey := generateRSAKey(RSABitsSize)
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{Country: []string{"CN"}, Organization: []string{"chrelyonly"}},
		NotBefore:             now,
		NotAfter:              now.AddDate(100, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          md5.New().Sum([]byte(now.String())),
	}
	generateCertificate(CACertFilename, CAKeyFilename, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	return caTemplate, caKey
}

// 生成并保存服务器证书
func generateServerCertificate(ca *x509.Certificate, caKey *rsa.PrivateKey, config Config) {
	serverKey := generateRSAKey(RSABitsSize)
	now := time.Now()
	serverTemplate := &x509.Certificate{
		SerialNumber:   big.NewInt(now.UnixNano()),
		Subject:        pkix.Name{Country: []string{"CN"}, Organization: []string{"chrelyonly"}, CommonName: "chrelyonly Server"},
		NotBefore:      now,
		NotAfter:       now.AddDate(100, 0, 0),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:       config.DNSNames,
		AuthorityKeyId: ca.SubjectKeyId,
	}

	// 解析 IP 地址字符串
	for _, ipStr := range config.IPAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			serverTemplate.IPAddresses = append(serverTemplate.IPAddresses, ip)
		} else {
			log.Printf("无效 IP 地址: %s", ipStr)
		}
	}

	generateCertificate(ServerCertFilename, ServerKeyFilename, serverTemplate, ca, &serverKey.PublicKey, caKey)
}

// 从配置文件加载 DNS 名称和 IP 地址
func loadConfig(filename string) Config {
	file, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("读取配置文件 %s 失败: %v", filename, err)
	}

	var config Config
	if err := json.Unmarshal(file, &config); err != nil {
		log.Fatalf("解析配置文件失败: %v", err)
	}
	return config
}

// 加载 CA 证书和私钥
func loadCA(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey) {
	caData := loadPEMData(certFile)
	ca, err := x509.ParseCertificate(caData.Bytes)
	if err != nil {
		log.Fatalf("解析 CA 证书失败: %v", err)
	}

	keyData := loadPEMData(keyFile)
	caKey, err := x509.ParsePKCS1PrivateKey(keyData.Bytes)
	if err != nil {
		log.Fatalf("解析 CA 私钥失败: %v", err)
	}
	return ca, caKey
}

// 加载 PEM 数据
func loadPEMData(filename string) *pem.Block {
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("读取文件 %s 失败: %v", filename, err)
	}
	block, _ := pem.Decode(data)
	return block
}

func main() {
	// 生成 CA 证书
	// caCert, caKey := generateCACertificate()

	// 加载现有的 CA 证书和私钥
	caCert, caKey := loadCA(CACertFilename, CAKeyFilename)

	// 加载配置文件
	config := loadConfig(ConfigFilename)

	// 生成服务器证书
	generateServerCertificate(caCert, caKey, config)
}
