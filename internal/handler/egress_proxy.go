package handler

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/egress"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const maxProxyCredentialBytes = 4096

type EgressProxyHandler struct {
	db     *database.DB
	cipher *egress.CredentialCipher
	logger *zap.Logger
}

func NewEgressProxyHandler(db *database.DB, cipher *egress.CredentialCipher, logger *zap.Logger) *EgressProxyHandler {
	return &EgressProxyHandler{db: db, cipher: cipher, logger: logger}
}

type egressProxyWriteRequest struct {
	Name        string          `json:"name"`
	Protocol    string          `json:"protocol"`
	Host        string          `json:"host"`
	Port        int             `json:"port"`
	Enabled     *bool           `json:"enabled,omitempty"`
	Credentials json.RawMessage `json:"credentials,omitempty"`
}

type egressProxyCredentialInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *EgressProxyHandler) List(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	limit, offset, err := parseEgressProxySearchWindow(c.Query("limit"), c.Query("offset"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	proxies, total, err := h.db.SearchEgressProxies(c.Request.Context(), session.UserID, session.Scope, c.Query("search"), limit, offset)
	if err != nil {
		h.logger.Error("列出出站代理失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取出站代理"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": proxies, "total": total, "limit": limit, "offset": offset})
}

func parseEgressProxySearchWindow(rawLimit, rawOffset string) (int, int, error) {
	limit, offset := 50, 0
	var err error
	if strings.TrimSpace(rawLimit) != "" {
		limit, err = strconv.Atoi(strings.TrimSpace(rawLimit))
		if err != nil || limit < 1 || limit > 100 {
			return 0, 0, fmt.Errorf("limit must be between 1 and 100")
		}
	}
	if strings.TrimSpace(rawOffset) != "" {
		offset, err = strconv.Atoi(strings.TrimSpace(rawOffset))
		if err != nil || offset < 0 {
			return 0, 0, fmt.Errorf("offset must be non-negative")
		}
	}
	return limit, offset, nil
}

func (h *EgressProxyHandler) Get(c *gin.Context) {
	proxy, err := h.db.GetEgressProxy(c.Request.Context(), c.Param("id"))
	if errors.Is(err, database.ErrEgressProxyNotFound) || errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "出站代理不存在"})
		return
	}
	if err != nil {
		h.logger.Error("读取出站代理失败", zap.String("proxy_id", strings.TrimSpace(c.Param("id"))), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取出站代理"})
		return
	}
	c.JSON(http.StatusOK, proxy)
}

func (h *EgressProxyHandler) Create(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	var req egressProxyWriteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "出站代理请求格式无效"})
		return
	}
	proxy := database.EgressProxy{
		ID: uuid.NewString(), Name: req.Name, Protocol: egress.UpstreamProtocol(req.Protocol),
		Host: req.Host, Port: req.Port, Enabled: true, OwnerUserID: session.UserID,
	}
	if req.Enabled != nil {
		proxy.Enabled = *req.Enabled
	}
	if err := normalizeEgressProxyWrite(&proxy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	credentialCiphertext, credentialUpdatedAt, err := h.resolveCredentialUpdate(proxy.ID, req.Credentials, "", nil, false)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	proxy.CredentialCiphertext = credentialCiphertext
	proxy.CredentialUpdatedAt = credentialUpdatedAt
	created, err := h.db.CreateEgressProxy(c.Request.Context(), proxy)
	if err != nil {
		writeEgressProxyStorageError(c, h.logger, "创建出站代理失败", "", err)
		return
	}
	c.JSON(http.StatusCreated, created)
}

func (h *EgressProxyHandler) Update(c *gin.Context) {
	proxyID := strings.TrimSpace(c.Param("id"))
	existing, err := h.db.GetEgressProxy(c.Request.Context(), proxyID)
	if errors.Is(err, database.ErrEgressProxyNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "出站代理不存在"})
		return
	}
	if err != nil {
		writeEgressProxyStorageError(c, h.logger, "读取待更新出站代理失败", proxyID, err)
		return
	}
	var req egressProxyWriteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "出站代理请求格式无效"})
		return
	}
	existing.Name = req.Name
	existing.Protocol = egress.UpstreamProtocol(req.Protocol)
	existing.Host = req.Host
	existing.Port = req.Port
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if err := normalizeEgressProxyWrite(&existing); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	existing.CredentialCiphertext, existing.CredentialUpdatedAt, err = h.resolveCredentialUpdate(
		existing.ID, req.Credentials, existing.CredentialCiphertext, existing.CredentialUpdatedAt, true,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updated, err := h.db.UpdateEgressProxy(c.Request.Context(), existing)
	if errors.Is(err, database.ErrEgressProxyNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "出站代理不存在"})
		return
	}
	if err != nil {
		writeEgressProxyStorageError(c, h.logger, "更新出站代理失败", proxyID, err)
		return
	}
	c.JSON(http.StatusOK, updated)
}

func normalizeEgressProxyWrite(proxy *database.EgressProxy) error {
	name, err := egress.ValidateUpstreamName(proxy.Name)
	if err != nil {
		return err
	}
	protocol, err := egress.ParseUpstreamProtocol(string(proxy.Protocol))
	if err != nil {
		return err
	}
	host, err := egress.NormalizeUpstreamHost(proxy.Host)
	if err != nil {
		return err
	}
	if err := egress.ValidateUpstreamPort(proxy.Port); err != nil {
		return err
	}
	proxy.Name = name
	proxy.Protocol = protocol
	proxy.Host = host
	return nil
}

func (h *EgressProxyHandler) Delete(c *gin.Context) {
	proxyID := strings.TrimSpace(c.Param("id"))
	if err := h.db.DeleteEgressProxy(c.Request.Context(), proxyID); errors.Is(err, database.ErrEgressProxyNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "出站代理不存在"})
		return
	} else if err != nil {
		writeEgressProxyStorageError(c, h.logger, "删除出站代理失败", proxyID, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// resolveCredentialUpdate preserves ciphertext only when an update omits the
// field. JSON null explicitly clears credentials. A credential object is
// validated, serialized, and encrypted without ever entering logs or errors.
func (h *EgressProxyHandler) resolveCredentialUpdate(
	proxyID string,
	raw json.RawMessage,
	existing string,
	existingUpdatedAt *time.Time,
	preserveWhenOmitted bool,
) (string, *time.Time, error) {
	if len(raw) == 0 {
		if preserveWhenOmitted {
			return existing, existingUpdatedAt, nil
		}
		return "", nil, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var credentials egressProxyCredentialInput
	if err := decoder.Decode(&credentials); err != nil {
		return "", nil, fmt.Errorf("credentials must contain only username and password")
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", nil, fmt.Errorf("credentials must be one JSON object")
	}
	credentials.Username = strings.TrimSpace(credentials.Username)
	if credentials.Username == "" {
		return "", nil, fmt.Errorf("proxy credential username is required; use null to clear credentials")
	}
	if !utf8.ValidString(credentials.Username) || !utf8.ValidString(credentials.Password) ||
		len(credentials.Username) > maxProxyCredentialBytes || len(credentials.Password) > maxProxyCredentialBytes {
		return "", nil, fmt.Errorf("proxy credential fields must be valid UTF-8 and at most %d bytes", maxProxyCredentialBytes)
	}
	plaintext, err := json.Marshal(egress.ProxyCredentials{Username: credentials.Username, Password: credentials.Password})
	if err != nil {
		return "", nil, fmt.Errorf("encode proxy credentials")
	}
	envelope, err := h.cipher.Encrypt(proxyID, plaintext)
	for i := range plaintext {
		plaintext[i] = 0
	}
	if err != nil {
		return "", nil, fmt.Errorf("encrypt proxy credentials")
	}
	now := time.Now().UTC()
	return envelope, &now, nil
}

func writeEgressProxyStorageError(c *gin.Context, logger *zap.Logger, message, proxyID string, err error) {
	fields := []zap.Field{zap.Error(err)}
	if strings.TrimSpace(proxyID) != "" {
		fields = append(fields, zap.String("proxy_id", proxyID))
	}
	logger.Error(message, fields...)
	c.JSON(http.StatusInternalServerError, gin.H{"error": "出站代理操作失败"})
}
