package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

const (
	RSABitsSize    = 2048
	ConfigFilename = "build/config.json"
)

// JSON 配置结构体
type Config struct {
	Keystore KeystoreConfig `json:"keystore"`
	CA       CAConfig       `json:"ca"`
}

type KeystoreConfig struct {
	FilePath string `json:"filePath"`
	Password string `json:"password"`
	KeyAlias string `json:"keyAlias"`
	KeyPass  string `json:"keyPass"`
}

type CAConfig struct {
	Country            string `json:"country"`
	Province           string `json:"province"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizationalUnit"`
	CommonName         string `json:"commonName"`
	ValidityYears      int    `json:"validityYears"`
}

type CertInfo struct {
	SerialNumber      string
	Subject           string
	Issuer            string
	NotBefore         string
	NotAfter          string
	MD5Fingerprint    string
	SHA1Fingerprint   string
	SHA256Fingerprint string
}

// 生成RSA私钥
func GenRsaPK(size int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, size)
}

// 计算证书指纹
func calculateFingerprints(certBytes []byte) (md5Str, sha1Str, sha256Str string) {
	md5Hash := md5.Sum(certBytes)
	md5Str = hex.EncodeToString(md5Hash[:])

	sha1Hash := sha1.Sum(certBytes)
	sha1Str = hex.EncodeToString(sha1Hash[:])

	sha256Hash := sha256.Sum256(certBytes)
	sha256Str = hex.EncodeToString(sha256Hash[:])

	return
}

// 解析证书信息
func parseCertInfo(certBytes []byte) (*CertInfo, error) {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	md5Str, sha1Str, sha256Str := calculateFingerprints(certBytes)

	return &CertInfo{
		SerialNumber:      cert.SerialNumber.String(),
		Subject:           cert.Subject.String(),
		Issuer:            cert.Issuer.String(),
		NotBefore:         cert.NotBefore.Format("2006-01-02 15:04:05"),
		NotAfter:          cert.NotAfter.Format("2006-01-02 15:04:05"),
		MD5Fingerprint:    md5Str,
		SHA1Fingerprint:   sha1Str,
		SHA256Fingerprint: sha256Str,
	}, nil
}

// 生成带时间戳的文件名
func generateTimestampedFilename(basePath string) (string, string) {
	timestamp := time.Now().Format("20060102-150405")
	ext := filepath.Ext(basePath)
	base := basePath[:len(basePath)-len(ext)]

	jksPath := fmt.Sprintf("%s-%s%s", base, timestamp, ext)
	infoPath := fmt.Sprintf("%s-%s.txt", base, timestamp)

	return jksPath, infoPath
}

// 保存证书信息到文件
func saveCertInfoToFile(filename string, cfg *Config, certInfo *CertInfo) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "="+strings.Repeat("=", 50)+"\n")
	fmt.Fprintf(file, "APK签名证书信息\n")
	fmt.Fprintf(file, "="+strings.Repeat("=", 50)+"\n\n")

	fmt.Fprintf(file, "证书信息：\n")
	fmt.Fprintf(file, "-"+strings.Repeat("-", 50)+"\n")
	fmt.Fprintf(file, "Keystore 路径: %s\n", cfg.Keystore.FilePath)
	fmt.Fprintf(file, "Key Alias: %s\n", cfg.Keystore.KeyAlias)
	fmt.Fprintf(file, "Keystore 密码: %s\n", cfg.Keystore.Password)
	fmt.Fprintf(file, "Key 密码: %s\n", cfg.Keystore.KeyPass)
	fmt.Fprintf(file, "\n")

	fmt.Fprintf(file, "证书详情：\n")
	fmt.Fprintf(file, "序列号: %s\n", certInfo.SerialNumber)
	fmt.Fprintf(file, "主题: %s\n", certInfo.Subject)
	fmt.Fprintf(file, "颁发者: %s\n", certInfo.Issuer)
	fmt.Fprintf(file, "有效期: %s 至 %s\n", certInfo.NotBefore, certInfo.NotAfter)
	fmt.Fprintf(file, "\n")

	fmt.Fprintf(file, "证书指纹：\n")
	fmt.Fprintf(file, "MD5: %s\n", certInfo.MD5Fingerprint)
	fmt.Fprintf(file, "SHA1: %s\n", certInfo.SHA1Fingerprint)
	fmt.Fprintf(file, "SHA256: %s\n", certInfo.SHA256Fingerprint)
	fmt.Fprintf(file, "="+strings.Repeat("=", 50)+"\n")

	return nil
}

// 从 JSON 文件读取配置
func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// 生成自签名证书和 keystore
func generateAPKCert(cfg *Config) (*CertInfo, error) {
	key, err := GenRsaPK(RSABitsSize)
	if err != nil {
		return nil, err
	}

	// 构建证书主题信息
	subject := pkix.Name{
		Country:            []string{cfg.CA.Country},
		Province:           []string{cfg.CA.Province},
		Organization:       []string{cfg.CA.Organization},
		OrganizationalUnit: []string{cfg.CA.OrganizationalUnit},
		CommonName:         cfg.CA.CommonName,
	}

	// 证书模板
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(cfg.CA.ValidityYears, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	// 自签名证书
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	// 解析证书信息
	certInfo, err := parseCertInfo(certBytes)
	if err != nil {
		return nil, err
	}

	// 保存到 JKS
	os.MkdirAll("build", 0755)
	ks := keystore.New()
	entry := keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       x509.MarshalPKCS1PrivateKey(key),
		CertificateChain: []keystore.Certificate{{Type: "X509", Content: certBytes}},
	}
	if err := ks.SetPrivateKeyEntry(cfg.Keystore.KeyAlias, entry, []byte(cfg.Keystore.KeyPass)); err != nil {
		return nil, err
	}

	f, err := os.Create(cfg.Keystore.FilePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if err := ks.Store(f, []byte(cfg.Keystore.Password)); err != nil {
		return nil, err
	}

	return certInfo, nil
}

func main() {
	// 尝试读取配置
	cfg, err := loadConfig(ConfigFilename)
	if err != nil {
		log.Println("加载配置失败，使用默认值")
		cfg = &Config{
			Keystore: KeystoreConfig{
				FilePath: "build/my-release-key.jks",
				Password: "chrelyonly",
				KeyAlias: "chrelyonly",
				KeyPass:  "chrelyonly",
			},
			CA: CAConfig{
				Country:            "CN",
				Province:           "Yunnan",
				Organization:       "chrelyonly",
				OrganizationalUnit: "chrelyonly",
				CommonName:         "chrelyonly CA",
				ValidityYears:      100,
			},
		}
	}

	// 生成带时间戳的文件名
	jksPath, infoPath := generateTimestampedFilename(cfg.Keystore.FilePath)

	// 更新配置中的文件路径
	cfg.Keystore.FilePath = jksPath

	certInfo, err := generateAPKCert(cfg)
	if err != nil {
		log.Fatalf("生成APK签名证书失败: %v", err)
	}

	// 保存证书信息到文件
	if err := saveCertInfoToFile(infoPath, cfg, certInfo); err != nil {
		log.Printf("保存证书信息文件失败: %v", err)
	}

	fmt.Println("=" + strings.Repeat("=", 50))
	fmt.Println("APK签名证书生成成功！")
	fmt.Println("=" + strings.Repeat("=", 50))
	fmt.Println()
	fmt.Println("证书信息：")
	fmt.Println("-" + strings.Repeat("-", 50))
	fmt.Printf("Keystore 路径: %s\n", cfg.Keystore.FilePath)
	fmt.Printf("证书信息文件: %s\n", infoPath)
	fmt.Printf("Key Alias: %s\n", cfg.Keystore.KeyAlias)
	fmt.Printf("Keystore 密码: %s\n", cfg.Keystore.Password)
	fmt.Printf("Key 密码: %s\n", cfg.Keystore.KeyPass)
	fmt.Println()
	fmt.Println("证书详情：")
	fmt.Printf("序列号: %s\n", certInfo.SerialNumber)
	fmt.Printf("主题: %s\n", certInfo.Subject)
	fmt.Printf("颁发者: %s\n", certInfo.Issuer)
	fmt.Printf("有效期: %s 至 %s\n", certInfo.NotBefore, certInfo.NotAfter)
	fmt.Println()
	fmt.Println("证书指纹：")
	fmt.Printf("MD5: %s\n", certInfo.MD5Fingerprint)
	fmt.Printf("SHA1: %s\n", certInfo.SHA1Fingerprint)
	fmt.Printf("SHA256: %s\n", certInfo.SHA256Fingerprint)
	fmt.Println("=" + strings.Repeat("=", 50))
}
