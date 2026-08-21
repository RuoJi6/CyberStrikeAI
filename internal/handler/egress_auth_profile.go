package handler

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/egress"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type EgressAuthProfileHandler struct {
	db     *database.DB
	cipher *egress.CredentialCipher
	logger *zap.Logger
}

func NewEgressAuthProfileHandler(db *database.DB, cipher *egress.CredentialCipher, logger *zap.Logger) *EgressAuthProfileHandler {
	return &EgressAuthProfileHandler{db: db, cipher: cipher, logger: logger}
}

type egressAuthProfileWriteRequest struct {
	Name       string          `json:"name"`
	HeaderName string          `json:"headerName"`
	Enabled    *bool           `json:"enabled,omitempty"`
	Credential json.RawMessage `json:"credential,omitempty"`
}

func (h *EgressAuthProfileHandler) List(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	profiles, err := h.db.ListEgressAuthProfiles(c.Request.Context(), session.UserID, session.ScopeFor("egress:read"))
	if err != nil {
		h.logger.Error("列出出站认证档案失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取出站认证档案"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": profiles})
}

func (h *EgressAuthProfileHandler) Get(c *gin.Context) {
	profile, err := h.db.GetEgressAuthProfile(c.Request.Context(), c.Param("id"))
	if errors.Is(err, database.ErrEgressAuthProfileNotFound) || errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "出站认证档案不存在"})
		return
	}
	if err != nil {
		h.logger.Error("读取出站认证档案失败", zap.String("auth_profile_id", strings.TrimSpace(c.Param("id"))), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取出站认证档案"})
		return
	}
	c.JSON(http.StatusOK, profile)
}

func (h *EgressAuthProfileHandler) Create(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	var request egressAuthProfileWriteRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "出站认证档案请求格式无效"})
		return
	}
	profile := database.EgressAuthProfile{
		ID: uuid.NewString(), Name: request.Name, HeaderName: request.HeaderName,
		Enabled: true, OwnerUserID: session.UserID,
	}
	if request.Enabled != nil {
		profile.Enabled = *request.Enabled
	}
	ciphertext, updatedAt, err := h.resolveCredential(profile.ID, request.Credential, "", nil, false)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	profile.CredentialCiphertext = ciphertext
	profile.CredentialUpdatedAt = updatedAt
	created, err := h.db.CreateEgressAuthProfile(c.Request.Context(), profile)
	if err != nil {
		h.logger.Error("创建出站认证档案失败", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": safeAuthProfileStorageError(err)})
		return
	}
	c.JSON(http.StatusCreated, created)
}

func (h *EgressAuthProfileHandler) Update(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	existing, err := h.db.GetEgressAuthProfile(c.Request.Context(), id)
	if errors.Is(err, database.ErrEgressAuthProfileNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "出站认证档案不存在"})
		return
	}
	if err != nil {
		h.logger.Error("读取待更新出站认证档案失败", zap.String("auth_profile_id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取出站认证档案"})
		return
	}
	var request egressAuthProfileWriteRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "出站认证档案请求格式无效"})
		return
	}
	existing.Name = request.Name
	existing.HeaderName = request.HeaderName
	if request.Enabled != nil {
		existing.Enabled = *request.Enabled
	}
	ciphertext, updatedAt, err := h.resolveCredential(existing.ID, request.Credential,
		existing.CredentialCiphertext, existing.CredentialUpdatedAt, true)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	existing.CredentialCiphertext = ciphertext
	existing.CredentialUpdatedAt = updatedAt
	updated, err := h.db.UpdateEgressAuthProfile(c.Request.Context(), existing)
	if err != nil {
		h.logger.Error("更新出站认证档案失败", zap.String("auth_profile_id", id), zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": safeAuthProfileStorageError(err)})
		return
	}
	c.JSON(http.StatusOK, updated)
}

func (h *EgressAuthProfileHandler) Delete(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	err := h.db.DeleteEgressAuthProfile(c.Request.Context(), id)
	switch {
	case errors.Is(err, database.ErrEgressAuthProfileNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "出站认证档案不存在"})
	case errors.Is(err, database.ErrEgressAuthProfileInUse):
		c.JSON(http.StatusConflict, gin.H{"error": "出站认证档案正在被边界规则引用"})
	case err != nil:
		h.logger.Error("删除出站认证档案失败", zap.String("auth_profile_id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法删除出站认证档案"})
	default:
		c.Status(http.StatusNoContent)
	}
}

func (h *EgressAuthProfileHandler) resolveCredential(id string, raw json.RawMessage, current string, currentUpdated *time.Time, preserveOmitted bool) (string, *time.Time, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		if preserveOmitted {
			return current, currentUpdated, nil
		}
		return "", nil, nil
	}
	if bytes.Equal(trimmed, []byte("null")) {
		return "", nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	var credential string
	if err := decoder.Decode(&credential); err != nil {
		return "", nil, errors.New("credential must be a string, null, or omitted")
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return "", nil, errors.New("credential must contain one JSON string")
	}
	if err := egress.ValidateAuthHeaderValue(credential); err != nil {
		return "", nil, err
	}
	if h == nil || h.cipher == nil {
		return "", nil, errors.New("credential encryption is unavailable")
	}
	ciphertext, err := h.cipher.EncryptAuthProfile(id, []byte(credential))
	if err != nil {
		return "", nil, errors.New("credential encryption failed")
	}
	now := time.Now().UTC()
	return ciphertext, &now, nil
}

func safeAuthProfileStorageError(err error) string {
	if err == nil {
		return ""
	}
	return "无法保存出站认证档案"
}
