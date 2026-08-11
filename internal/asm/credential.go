package asm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const credentialKeyEnv = "CYBERSTRIKE_ASM_CREDENTIAL_KEY"

type credentialCipher struct {
	aead cipher.AEAD
}

func newCredentialCipher(databasePath string) (*credentialCipher, error) {
	key, err := loadCredentialKey(databasePath)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("初始化 ASM 凭据加密失败: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("初始化 ASM 凭据 GCM 失败: %w", err)
	}
	return &credentialCipher{aead: aead}, nil
}

func decodeCredentialKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if key, err := encoding.DecodeString(raw); err == nil && len(key) == 32 {
			return key, nil
		}
	}
	return nil, fmt.Errorf("ASM 凭据主密钥必须是 base64 编码的 32 字节随机值")
}

func loadCredentialKey(databasePath string) ([]byte, error) {
	if raw := strings.TrimSpace(os.Getenv(credentialKeyEnv)); raw != "" {
		key, err := decodeCredentialKey(raw)
		if err != nil {
			return nil, fmt.Errorf("%s 无效: %w", credentialKeyEnv, err)
		}
		return key, nil
	}

	keyPath := filepath.Join(filepath.Dir(databasePath), ".asm-credential-key")
	if raw, err := os.ReadFile(keyPath); err == nil {
		_ = os.Chmod(keyPath, 0o600)
		return decodeCredentialKey(string(raw))
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("读取 ASM 凭据主密钥失败: %w", err)
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("生成 ASM 凭据主密钥失败: %w", err)
	}
	encoded := base64.RawStdEncoding.EncodeToString(key) + "\n"
	file, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			raw, readErr := os.ReadFile(keyPath)
			if readErr != nil {
				return nil, fmt.Errorf("并发读取 ASM 凭据主密钥失败: %w", readErr)
			}
			return decodeCredentialKey(string(raw))
		}
		return nil, fmt.Errorf("创建 ASM 凭据主密钥失败: %w", err)
	}
	if _, err := file.WriteString(encoded); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("写入 ASM 凭据主密钥失败: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("保存 ASM 凭据主密钥失败: %w", err)
	}
	return key, nil
}

func credentialAAD(resourceID string) []byte {
	return []byte("cyberstrike-asm-resource:" + strings.TrimSpace(resourceID))
}

func (c *credentialCipher) encrypt(resourceID, plaintext string) (string, error) {
	if strings.TrimSpace(plaintext) == "" {
		return "", nil
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("生成 ASM 凭据随机数失败: %w", err)
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(plaintext), credentialAAD(resourceID))
	return "v1:" + base64.RawStdEncoding.EncodeToString(sealed), nil
}

func (c *credentialCipher) decrypt(resourceID, ciphertext string) (string, error) {
	if strings.TrimSpace(ciphertext) == "" {
		return "", nil
	}
	if !strings.HasPrefix(ciphertext, "v1:") {
		return "", fmt.Errorf("不支持的 ASM 凭据密文版本")
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(ciphertext, "v1:"))
	if err != nil {
		return "", fmt.Errorf("解析 ASM 凭据密文失败: %w", err)
	}
	if len(raw) < c.aead.NonceSize() {
		return "", fmt.Errorf("ASM 凭据密文长度无效")
	}
	nonce, encrypted := raw[:c.aead.NonceSize()], raw[c.aead.NonceSize():]
	plain, err := c.aead.Open(nil, nonce, encrypted, credentialAAD(resourceID))
	if err != nil {
		return "", fmt.Errorf("解密 ASM 凭据失败: %w", err)
	}
	return string(plain), nil
}
