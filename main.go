package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	RSABitsSize        = 2048
	CACertFilename     = "build/ca.pem"
	CAKeyFilename      = "build/ca.key"
	ServerCertFilename = "build/server.pem"
	ServerKeyFilename  = "build/server.key"
	ConfigFilename     = "build/config.json" // 配置文件名
)

// 配置文件的结构体
type Config struct {
	IPs     []string `json:"ips"`     // 存储IP地址
	Domains []string `json:"domains"` // 存储域名
	CA      CAConfig `json:"ca"`      // 存储CA配置
}

type CAConfig struct {
	Country            string `json:"country"`            // 国家
	Province           string `json:"province"`           // 省份
	Organization       string `json:"organization"`       // 组织
	OrganizationalUnit string `json:"organizationalUnit"` // 组织单位
	CommonName         string `json:"commonName"`         // 公共名称
	ValidityYears      int    `json:"validityYears"`      // 有效期（年）
}

// 生成RSA私钥
func GenRsaPK(size int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, size)
}

// 生成并保存PEM格式文件
func savePEM(filename string, blockType string, bytes []byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{Type: blockType, Bytes: bytes})
}

// 从JSON文件加载配置
func loadConfig(filename string) (*Config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// 生成CA证书和私钥
func generateCA(caConfig CAConfig) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := GenRsaPK(RSABitsSize)
	if err != nil {
		return nil, nil, err
	}

	// CA证书信息
	caInfo := pkix.Name{
		Country:            []string{caConfig.Country},
		Province:           []string{caConfig.Province},
		Organization:       []string{caConfig.Organization},
		OrganizationalUnit: []string{caConfig.OrganizationalUnit},
		CommonName:         caConfig.CommonName,
	}

	// CA证书配置
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               caInfo,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(caConfig.ValidityYears, 0, 0), // 使用配置中的有效期
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          md5.New().Sum([]byte(time.Now().String())),
	}

	// 使用CA私钥自签名生成证书
	certBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	// 保存CA证书和私钥
	if err := savePEM(CACertFilename, "CERTIFICATE", certBytes); err != nil {
		return nil, nil, err
	}
	if err := savePEM(CAKeyFilename, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)); err != nil {
		return nil, nil, err
	}

	return ca, key, nil
}

// 生成服务器证书
func generateServerCert(caConfig CAConfig, ca *x509.Certificate, caKey *rsa.PrivateKey, config *Config) error {
	key, err := GenRsaPK(RSABitsSize)
	if err != nil {
		return err
	}
	// 服务器证书信息
	serverInfo := pkix.Name{
		Country:            []string{caConfig.Country},
		Province:           []string{caConfig.Province},
		Organization:       []string{caConfig.Organization},
		OrganizationalUnit: []string{caConfig.OrganizationalUnit},
		CommonName:         caConfig.CommonName,
	}

	// 服务器证书配置
	serverCert := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano()),
		Subject:        serverInfo,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(caConfig.ValidityYears, 0, 0), // 1年有效期
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		AuthorityKeyId: ca.SubjectKeyId,
	}

	// 将配置中的 IP 地址添加到服务器证书
	for _, ip := range config.IPs {
		serverCert.IPAddresses = append(serverCert.IPAddresses, net.ParseIP(ip))
	}

	// 将配置中的域名添加到服务器证书
	for _, domain := range config.Domains {
		serverCert.DNSNames = append(serverCert.DNSNames, domain)
	}

	// 使用CA签发服务器证书
	certBytes, err := x509.CreateCertificate(rand.Reader, serverCert, ca, &key.PublicKey, caKey)
	if err != nil {
		return err
	}

	// 保存服务器证书和私钥
	if err := savePEM(ServerCertFilename, "CERTIFICATE", certBytes); err != nil {
		return err
	}
	if err := savePEM(ServerKeyFilename, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)); err != nil {
		return err
	}

	return nil
}

// LoadCA 从文件加载CA证书和私钥
func LoadCA(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey) {
	caData := loadPEMData(certFile)
	ca, err := x509.ParseCertificate(caData.Bytes)
	if err != nil {
		log.Fatalf("解析CA证书失败: %v", err)
	}

	keyData := loadPEMData(keyFile)
	caKey, err := x509.ParsePKCS1PrivateKey(keyData.Bytes)
	if err != nil {
		log.Fatalf("解析CA私钥失败: %v", err)
	}
	return ca, caKey
}

// loadPEMData 从文件加载PEM数据
func loadPEMData(filename string) *pem.Block {
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("读取文件 %s 失败: %v", filename, err)
	}
	block, _ := pem.Decode(data)
	return block
}

func main() {
	// 读取配置文件
	config, err := loadConfig(ConfigFilename)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	// 使用配置文件中的 CA 配置生成 CA 证书和私钥
	//ca, caKey, _ := generateCA(config.CA)
	ca, caKey := LoadCA(CACertFilename, CAKeyFilename)

	// 使用配置文件生成服务器证书
	if err := generateServerCert(config.CA, ca, caKey, config); err != nil {
		log.Fatalf("生成服务器证书失败: %v", err)
	}
	log.Println("服务器证书和私钥生成成功")
}
