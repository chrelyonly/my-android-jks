package main

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"math/big"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

const RSABitsSize = 2048

// ===== 请求与响应数据结构定义 =====

type KeystoreConfig struct {
	FileName string `json:"fileName"` // 生成文件名，如 "my-release-key.jks"
	Password string `json:"password"` // Keystore 密码
	KeyAlias string `json:"keyAlias"` // 别名
	KeyPass  string `json:"keyPass"`  // Key 密码
}

type CAConfig struct {
	Country            string `json:"country"`
	Province           string `json:"province"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizationalUnit"`
	CommonName         string `json:"commonName"`
	ValidityYears      int    `json:"validityYears"`
}

type GenerateAPKCertRequest struct {
	Keystore KeystoreConfig `json:"keystore"`
	CA       CAConfig       `json:"ca"`
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
	MD5Formatted      string // Android 常用带冒号大写格式
	SHA1Formatted     string
	SHA256Formatted   string
}

//go:embed public/*
var staticFS embed.FS

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.Use(corsMiddleware())

	// ===== 路由配置 =====
	r.POST("/generate-apk-cert", handleGenerateAPKCert)

	// ===== 静态资源与 SPA 路由适配 =====
	subFS, err := fs.Sub(staticFS, "public")
	if err != nil {
		// 没有 public 目录时不会崩溃，方便单独作为纯后端 API 运行
		fmt.Printf("⚠️ 提示: 未找到静态资源目录 public: %v\n", err)
	} else {
		httpFS := http.FS(subFS)
		r.NoRoute(func(c *gin.Context) {
			path := c.Request.URL.Path
			if strings.HasPrefix(path, "/generate") {
				return
			}
			f, err := subFS.Open(strings.TrimPrefix(path, "/"))
			if err == nil {
				_ = f.Close()
				http.FileServer(httpFS).ServeHTTP(c.Writer, c.Request)
				return
			}
			c.Request.URL.Path = "/"
			http.FileServer(httpFS).ServeHTTP(c.Writer, c.Request)
		})
	}

	fmt.Println("🚀 Android APK 证书签发 Web 服务已启动于 :8080...")
	if err := r.Run(":8080"); err != nil {
		fmt.Printf("❌ 服务启动失败: %v\n", err)
	}
}

// ===== HTTP 接口处理函数 =====

func handleGenerateAPKCert(c *gin.Context) {
	var req GenerateAPKCertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数解析失败: " + err.Error()})
		return
	}

	// 补全默认参数
	fillDefaultConfig(&req)

	// 生成 JKS 字节数组和证书详情信息
	jksBytes, certInfo, err := generateAPKCertBytes(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成 APK 证书失败: " + err.Error()})
		return
	}

	// 生成格式化的文本说明
	infoText := buildCertInfoText(&req, certInfo)

	// 打包 ZIP 字节流
	zipBuf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(zipBuf)

	// 写入 .jks 文件
	jksFileName := req.Keystore.FileName
	if !strings.HasSuffix(jksFileName, ".jks") {
		jksFileName += ".jks"
	}
	if err := addFileToZip(zipWriter, jksFileName, jksBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "打包 JKS 文件失败: " + err.Error()})
		return
	}

	// 写入 证书信息说明 .txt 文件
	infoFileName := strings.TrimSuffix(jksFileName, filepath.Ext(jksFileName)) + "-info.txt"
	if err := addFileToZip(zipWriter, infoFileName, []byte(infoText)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "打包说明文件失败: " + err.Error()})
		return
	}

	if err := zipWriter.Close(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "关闭 ZIP 流失败: " + err.Error()})
		return
	}

	// 返回 zip 流
	c.Header("Content-Disposition", "attachment; filename=apk-keystore.zip")
	c.Header("Content-Type", "application/zip")
	c.Data(http.StatusOK, "application/zip", zipBuf.Bytes())
}

// ===== 核心证书生成逻辑（纯内存操作） =====

func generateAPKCertBytes(cfg *GenerateAPKCertRequest) ([]byte, *CertInfo, error) {
	key, err := rsa.GenerateKey(rand.Reader, RSABitsSize)
	if err != nil {
		return nil, nil, fmt.Errorf("生成 RSA 密钥对失败: %w", err)
	}

	subject := pkix.Name{
		Country:            []string{cfg.CA.Country},
		Province:           []string{cfg.CA.Province},
		Organization:       []string{cfg.CA.Organization},
		OrganizationalUnit: []string{cfg.CA.OrganizationalUnit},
		CommonName:         cfg.CA.CommonName,
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("生成序列号失败: %w", err)
	}

	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now().Add(-10 * time.Minute),
		NotAfter:     time.Now().AddDate(cfg.CA.ValidityYears, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("创建 x509 证书失败: %w", err)
	}

	certInfo, err := parseCertInfo(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("解析证书信息失败: %w", err)
	}

	// 转换为 JKS 格式
	ks := keystore.New()
	// ✅ 正确：使用 PKCS#8 格式序列化私钥
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("序列化私钥失败(PKCS#8): %w", err)
	}

	entry := keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       privateKeyBytes,
		CertificateChain: []keystore.Certificate{{Type: "X509", Content: certBytes}},
	}

	if err := ks.SetPrivateKeyEntry(cfg.Keystore.KeyAlias, entry, []byte(cfg.Keystore.KeyPass)); err != nil {
		return nil, nil, fmt.Errorf("写入 KeyStore 失败: %w", err)
	}

	jksBuf := new(bytes.Buffer)
	if err := ks.Store(jksBuf, []byte(cfg.Keystore.Password)); err != nil {
		return nil, nil, fmt.Errorf("导出 KeyStore 字节流失败: %w", err)
	}

	return jksBuf.Bytes(), certInfo, nil
}

// ===== 工具函数与辅助处理 =====

func fillDefaultConfig(req *GenerateAPKCertRequest) {
	if req.Keystore.FileName == "" {
		req.Keystore.FileName = "release-key.jks"
	}
	if req.Keystore.Password == "" {
		req.Keystore.Password = "chrelyonly"
	}
	if req.Keystore.KeyAlias == "" {
		req.Keystore.KeyAlias = "chrelyonly"
	}
	if req.Keystore.KeyPass == "" {
		req.Keystore.KeyPass = "chrelyonly"
	}

	if req.CA.Country == "" {
		req.CA.Country = "CN"
	}
	if req.CA.Province == "" {
		req.CA.Province = "Yunnan"
	}
	if req.CA.Organization == "" {
		req.CA.Organization = "chrelyonly"
	}
	if req.CA.OrganizationalUnit == "" {
		req.CA.OrganizationalUnit = "chrelyonly"
	}
	if req.CA.CommonName == "" {
		req.CA.CommonName = "chrelyonly"
	}
	if req.CA.ValidityYears <= 0 {
		req.CA.ValidityYears = 30
	}
}

func formatFingerprint(hexStr string) string {
	hexStr = strings.ToUpper(hexStr)
	var result []string
	for i := 0; i < len(hexStr); i += 2 {
		if i+2 <= len(hexStr) {
			result = append(result, hexStr[i:i+2])
		}
	}
	return strings.Join(result, ":")
}

func parseCertInfo(certBytes []byte) (*CertInfo, error) {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	md5Hash := md5.Sum(certBytes)
	md5Str := hex.EncodeToString(md5Hash[:])

	sha1Hash := sha1.Sum(certBytes)
	sha1Str := hex.EncodeToString(sha1Hash[:])

	sha256Hash := sha256.Sum256(certBytes)
	sha256Str := hex.EncodeToString(sha256Hash[:])

	return &CertInfo{
		SerialNumber:      cert.SerialNumber.String(),
		Subject:           cert.Subject.String(),
		Issuer:            cert.Issuer.String(),
		NotBefore:         cert.NotBefore.Format("2006-01-02 15:04:05"),
		NotAfter:          cert.NotAfter.Format("2006-01-02 15:04:05"),
		MD5Fingerprint:    md5Str,
		SHA1Fingerprint:   sha1Str,
		SHA256Fingerprint: sha256Str,
		MD5Formatted:      formatFingerprint(md5Str),
		SHA1Formatted:     formatFingerprint(sha1Str),
		SHA256Formatted:   formatFingerprint(sha256Str),
	}, nil
}

func buildCertInfoText(cfg *GenerateAPKCertRequest, certInfo *CertInfo) string {
	divider := "=" + strings.Repeat("=", 58) + "\n"
	subDivider := "-" + strings.Repeat("-", 58) + "\n"

	var sb strings.Builder
	sb.WriteString(divider)
	sb.WriteString("Android APK 签名证书信息\n")
	sb.WriteString(divider + "\n")

	sb.WriteString("Keystore 配置信息：\n")
	sb.WriteString(subDivider)
	sb.WriteString(fmt.Sprintf("文件名称:     %s\n", cfg.Keystore.FileName))
	sb.WriteString(fmt.Sprintf("Key Alias:    %s\n", cfg.Keystore.KeyAlias))
	sb.WriteString(fmt.Sprintf("Keystore 密码:%s\n", cfg.Keystore.Password))
	sb.WriteString(fmt.Sprintf("Key 密码:     %s\n", cfg.Keystore.KeyPass))
	sb.WriteString("\n")

	sb.WriteString("证书详情：\n")
	sb.WriteString(subDivider)
	sb.WriteString(fmt.Sprintf("序列号: %s\n", certInfo.SerialNumber))
	sb.WriteString(fmt.Sprintf("主题:   %s\n", certInfo.Subject))
	sb.WriteString(fmt.Sprintf("有效期: %s 至 %s\n", certInfo.NotBefore, certInfo.NotAfter))
	sb.WriteString("\n")

	sb.WriteString("Android 开发者常用指纹 (微信/Google等开放平台绑定用)：\n")
	sb.WriteString(subDivider)
	sb.WriteString(fmt.Sprintf("MD5:    %s\n", certInfo.MD5Formatted))
	sb.WriteString(fmt.Sprintf("SHA1:   %s\n", certInfo.SHA1Formatted))
	sb.WriteString(fmt.Sprintf("SHA256: %s\n", certInfo.SHA256Formatted))
	sb.WriteString("\n")

	sb.WriteString("原始指纹 (HEX)：\n")
	sb.WriteString(subDivider)
	sb.WriteString(fmt.Sprintf("MD5:    %s\n", certInfo.MD5Fingerprint))
	sb.WriteString(fmt.Sprintf("SHA1:   %s\n", certInfo.SHA1Fingerprint))
	sb.WriteString(fmt.Sprintf("SHA256: %s\n", certInfo.SHA256Fingerprint))
	sb.WriteString(divider)

	return sb.String()
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
		c.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Disposition")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
