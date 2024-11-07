package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	RSABitsSize        = 4096
	CACertFilename     = "ca.pem"
	CAKeyFilename      = "ca.key"
	ServerCertFilename = "server.pem"
	ServerKeyFilename  = "server.key"
)

// GenerateRSAKey 生成指定位数的 RSA 私钥
func GenerateRSAKey(bits int) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Fatalf("生成 RSA 私钥失败: %v", err)
	}
	return key
}

// SavePEMFile 保存 PEM 编码的块到文件
func SavePEMFile(filename string, pemType string, data []byte) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("创建文件 %s 失败: %v", filename, err)
	}
	defer file.Close()

	if err := pem.Encode(file, &pem.Block{Type: pemType, Bytes: data}); err != nil {
		log.Fatalf("写入 PEM 块到文件 %s 失败: %v", filename, err)
	}
	log.Printf("文件 %s 保存成功", filename)
}

// GenerateCertificate 生成证书并保存到文件
func GenerateCertificate(filename, keyFilename string, template, parent *x509.Certificate, pubKey, parentPrivKey interface{}) {
	certData, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, parentPrivKey)
	if err != nil {
		log.Fatalf("生成证书失败: %v", err)
	}

	SavePEMFile(filename, "CERTIFICATE", certData)

	if privKey, ok := parentPrivKey.(*rsa.PrivateKey); ok {
		SavePEMFile(keyFilename, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(privKey))
	}
}

// GenerateCACertificate 生成并保存 CA 证书
func GenerateCACertificate() (*x509.Certificate, *rsa.PrivateKey) {
	caKey := GenerateRSAKey(RSABitsSize)
	now := time.Now()

	caTemplate := &x509.Certificate{
		Version:               2,
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{Country: []string{"CN"}, Province: []string{"yunnan"}, Organization: []string{"chrelyonly"}, OrganizationalUnit: []string{"chrelyonly"}, CommonName: "chrelyonly"},
		Issuer:                pkix.Name{Country: []string{"CN"}, Province: []string{"yunnan"}, Organization: []string{"chrelyonly"}, OrganizationalUnit: []string{"chrelyonly"}, CommonName: "chrelyonly"},
		NotBefore:             now,
		NotAfter:              now.AddDate(100, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          md5.New().Sum([]byte(now.String())),
	}

	GenerateCertificate(CACertFilename, CAKeyFilename, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	return caTemplate, caKey
}

// GenerateServerCertificate 生成并保存服务器证书，由指定 CA 签名
func GenerateServerCertificate(ca *x509.Certificate, caKey *rsa.PrivateKey) {
	serverKey := GenerateRSAKey(RSABitsSize)
	now := time.Now()

	serverTemplate := &x509.Certificate{
		Version:        2,
		SerialNumber:   big.NewInt(now.UnixNano()),
		Subject:        pkix.Name{Country: []string{"CN"}, Province: []string{"yunnan"}, Organization: []string{"chrelyonly"}, OrganizationalUnit: []string{"chrelyonly"}, CommonName: "chrelyonly Server"},
		NotBefore:      now,
		NotAfter:       now.AddDate(100, 0, 0),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:       []string{"localhost", "wutixi.hnyxtour.com"},
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("172.17.255.149")},
		AuthorityKeyId: ca.SubjectKeyId,
	}

	GenerateCertificate(ServerCertFilename, ServerKeyFilename, serverTemplate, ca, &serverKey.PublicKey, caKey)
}

func main() {
	// 生成 CA 证书
	//caCert, caKey := GenerateCACertificate()

	// 加载 CA 证书和私钥
	caCert, caKey := LoadCA(CACertFilename, CAKeyFilename)

	// 生成服务器证书
	GenerateServerCertificate(caCert, caKey)
}

// LoadCA 从文件加载 CA 证书和私钥
func LoadCA(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey) {
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

// loadPEMData 从文件加载 PEM 数据
func loadPEMData(filename string) *pem.Block {
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("读取文件 %s 失败: %v", filename, err)
	}
	block, _ := pem.Decode(data)
	return block
}
