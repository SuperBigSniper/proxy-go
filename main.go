package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

func GenSSL(CommonName string) {
	// 生成 RSA 私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// 创建证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"proxy-go"},
			CommonName:   CommonName,
			Country:      []string{"CN"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 100),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// 生成自签名证书
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(err)
	}

	// 将证书编码为 PEM 格式
	certOut, err := os.Create("cert.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	// 将私钥编码为 PEM 格式
	keyOut, err := os.Create("key.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	keyOut.Close()
}

func If[T any](cond bool, trueVal T, falseVal T) T {
	if cond {
		return trueVal
	} else {
		return falseVal
	}
}

type Config struct {
	Target   string
	CertFile string `yaml:"certFile"`
	KeyFile  string `yaml:"keyFile"`
	Port     string
}

func main() {
	file, err := os.OpenFile("./config.yaml", os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		log.Println(err.Error())
		return
	}
	stat, _ := file.Stat()
	if stat.Size() == 0 {
		file.WriteString(`# 代理的目标服务器地址
# target: https://local.demo.cn:2333
# 指定证书的文件路径
# certFile: /Users/xxx/Documents/cert.pem
# 指定证书的私钥文件路径
# keyFile: /Users/xxx/Documents/key.pem
# 配置代理服务器的端口
# port: 9111`)
	}
	file.Close() // 确保文件在操作结束后关闭

	yamlFile, err := os.ReadFile("./config.yaml")
	if err != nil {
		log.Println(err.Error())
		return
	}

	config := Config{
		Port:     "9111",
		CertFile: "./cert.pem",
		KeyFile:  "./key.pem",
	}

	err = yaml.Unmarshal([]byte(yamlFile), &config)
	if err != nil {
		log.Println(err.Error())
		return
	}

	if config.Target == "" {
		log.Fatal("未指定target配置, 已自动自动退出")
		return
	} else {
		log.Println("target配置为: " + config.Target)
	}

	if config.CertFile == "" || config.KeyFile == "" {
		GenSSL(config.Target)
		log.Println("未指定certFile或者KeyFile配置, 已自动在当前目录生成证书，请双击信任")
		return
	}

	target, error := url.Parse(config.Target)

	if error != nil {
		log.Fatal(error)
		return
	}

	// 创建一个ReverseProxy，它将请求转发到目标URL
	proxy := httputil.ReverseProxy{
		Director: func(req *http.Request) {

			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			Origin := req.Header.Get("Origin")
			if Origin == "" {
				Origin = "*"
			}
			req.Header.Set("Access-Control-Allow-Origin", Origin)
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		Origin := req.Header.Get("Origin")
		if req.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", If(Origin != "", Origin, "*"))
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", req.Header.Get("Access-Control-Request-Headers"))
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		proxy.ServeHTTP(w, req)
	})

	log.Fatal(http.ListenAndServeTLS(
		":"+config.Port,
		config.CertFile,
		config.KeyFile,
		// http.HandlerFunc()
		nil,
	))
}
