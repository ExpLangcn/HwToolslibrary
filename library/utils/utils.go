package utils

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"math/rand"
	"time"
)

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randomString(n int) string {
	rand.Seed(time.Now().UnixNano())

	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// 使用方法：
// randStr := randomString(10) // 生成长度为10的随机字符串

func md5Encryption(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

// 使用方法：
// encryptedText := md5Encryption("your string")

func base64Encryption(text string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(text))
	return encoded
}

// 使用方法：
// encryptedText := base64Encryption("your string")

func base64Decryption(encryptedText string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// 使用方法：
// decryptedText, err := base64Decryption("your encoded string")
// if err != nil {
//     // 处理错误
// }
