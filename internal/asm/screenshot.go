package asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cyberstrike-ai/internal/database"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const asmScreenshotMaxBytes = 10 * 1024 * 1024

type screenshotFetcher interface {
	FetchScreenshot(context.Context, *Connection, string) ([]byte, string, error)
}

type ScreenshotSyncResult struct {
	TaskID      string                    `json:"task_id"`
	Discovered  int                       `json:"discovered"`
	Downloaded  int                       `json:"downloaded"`
	Skipped     int                       `json:"skipped"`
	Errors      []string                  `json:"errors"`
	Screenshots []*database.ASMScreenshot `json:"screenshots"`
}

type screenshotReference struct {
	URL   string
	Label string
}

func resolveScreenshotURL(baseURL, reference string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("ASM 基础地址无效")
	}
	reference = strings.TrimSpace(reference)
	if reference == "" || len(reference) > 4096 {
		return "", fmt.Errorf("截图地址为空或过长")
	}
	ref, err := url.Parse(reference)
	if err != nil {
		return "", fmt.Errorf("截图地址无效: %w", err)
	}
	resolved := base.ResolveReference(ref)
	if resolved.User != nil || !strings.EqualFold(resolved.Scheme, base.Scheme) || !strings.EqualFold(resolved.Host, base.Host) {
		return "", fmt.Errorf("截图地址必须与 ASM 资源同源")
	}
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return "", fmt.Errorf("截图地址仅支持 http 或 https")
	}
	return resolved.String(), nil
}

func resolveARLScreenshotURL(baseURL, reference string) (string, error) {
	endpoint, err := resolveScreenshotURL(baseURL, reference)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("解析 ARL 截图地址失败: %w", err)
	}
	// ARL 2.6.x stores screenshot references as /image/<task>/<file>, while
	// nginx only proxies its Flask image namespace below /api/. Requesting the
	// stored path directly returns the SPA index instead of image bytes.
	if strings.HasPrefix(parsed.Path, "/image/") {
		parsed.Path = "/api" + parsed.Path
	}
	return parsed.String(), nil
}

func imageContentType(data []byte) (string, string, error) {
	switch {
	case len(data) >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff:
		return "image/jpeg", ".jpg", nil
	case len(data) >= 8 && bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}):
		return "image/png", ".png", nil
	case len(data) >= 6 && (bytes.Equal(data[:6], []byte("GIF87a")) || bytes.Equal(data[:6], []byte("GIF89a"))):
		return "image/gif", ".gif", nil
	case len(data) >= 12 && bytes.Equal(data[:4], []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WEBP")):
		return "image/webp", ".webp", nil
	default:
		return "", "", fmt.Errorf("返回内容不是支持的图片格式")
	}
}

func downloadScreenshot(ctx context.Context, client *http.Client, endpoint string, headers map[string]string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, "", fmt.Errorf("创建截图请求失败: %w", err)
	}
	// XingRin's DRF image action negotiates a binary renderer and returns 406
	// for a browser-style enumerated image list. Keep image preferred while
	// accepting the provider's binary content type.
	req.Header.Set("Accept", "image/*, */*;q=0.8")
	req.Header.Set("User-Agent", "CyberStrikeAI-ASM/1.0")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("请求 ASM 截图失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", fmt.Errorf("ASM 截图 HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, asmScreenshotMaxBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("读取 ASM 截图失败: %w", err)
	}
	if len(data) > asmScreenshotMaxBytes {
		return nil, "", fmt.Errorf("ASM 截图超过 10 MiB 限制")
	}
	contentType, _, err := imageContentType(data)
	if err != nil {
		return nil, "", err
	}
	return data, contentType, nil
}

func (a *ARLAdapter) FetchScreenshot(ctx context.Context, conn *Connection, reference string) ([]byte, string, error) {
	endpoint, err := resolveARLScreenshotURL(conn.Resource.BaseURL, reference)
	if err != nil {
		return nil, "", err
	}
	token, err := a.token(ctx, conn)
	if err != nil {
		return nil, "", err
	}
	return downloadScreenshot(ctx, arlHTTPClient(conn.Resource.VerifyTLS), endpoint, map[string]string{"Token": token})
}

func (a *XingRinAdapter) FetchScreenshot(ctx context.Context, conn *Connection, reference string) ([]byte, string, error) {
	endpoint, err := resolveScreenshotURL(conn.Resource.BaseURL, reference)
	if err != nil {
		return nil, "", err
	}
	client, _, err := a.session(ctx, conn)
	if err != nil {
		return nil, "", err
	}
	return downloadScreenshot(ctx, client, endpoint, nil)
}

func (a *ScopeSentryAdapter) FetchScreenshot(ctx context.Context, conn *Connection, reference string) ([]byte, string, error) {
	endpoint, err := resolveScreenshotURL(conn.Resource.BaseURL, reference)
	if err != nil {
		return nil, "", err
	}
	client, token, err := a.session(ctx, conn)
	if err != nil {
		return nil, "", err
	}
	return downloadScreenshot(ctx, client, endpoint, map[string]string{"Authorization": "Bearer " + token})
}

func screenshotKey(key string) bool {
	key = strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(strings.TrimSpace(key)))
	switch key {
	case "screenshot", "screenshoturl", "screenshotpath", "image", "imageurl", "imagepath", "webshot", "webshoturl":
		return true
	default:
		return false
	}
}

func screenshotLabel(object map[string]interface{}) string {
	for _, key := range []string{"url", "site", "domain", "ip", "title", "name"} {
		if value := meaningfulString(object[key]); value != "" {
			if len(value) > 300 {
				value = value[:300]
			}
			return value
		}
	}
	return ""
}

func collectScreenshotReferences(value interface{}) []screenshotReference {
	seen := make(map[string]struct{})
	result := make([]screenshotReference, 0)
	var walk func(interface{})
	walk = func(current interface{}) {
		if len(result) >= 200 {
			return
		}
		switch item := current.(type) {
		case map[string]interface{}:
			label := screenshotLabel(item)
			for key, raw := range item {
				if screenshotKey(key) {
					if reference := meaningfulString(raw); strings.HasPrefix(reference, "/") || strings.HasPrefix(reference, "http://") || strings.HasPrefix(reference, "https://") {
						if _, exists := seen[reference]; !exists {
							seen[reference] = struct{}{}
							result = append(result, screenshotReference{URL: reference, Label: label})
						}
					}
				}
				walk(raw)
			}
		case []interface{}:
			for _, child := range item {
				walk(child)
			}
		}
	}
	walk(value)
	return result
}

func enrichScreenshotURLs(items []*database.ASMScreenshot) []*database.ASMScreenshot {
	for _, item := range items {
		item.URL = "/api/asm/screenshots/" + url.PathEscape(item.ID) + "/content"
	}
	return items
}

func (s *Service) cacheTaskScreenshotPayload(ctx context.Context, id string, payload interface{}) (ScreenshotSyncResult, error) {
	item, err := s.db.GetASMTask(id)
	if err != nil {
		return ScreenshotSyncResult{}, err
	}
	references := collectScreenshotReferences(payload)
	result := ScreenshotSyncResult{TaskID: item.ID, Discovered: len(references), Errors: []string{}}
	conn, adapter, err := s.connection(item.ResourceID, false)
	if err != nil {
		return result, err
	}
	fetcher, ok := adapter.(screenshotFetcher)
	if !ok {
		return result, fmt.Errorf("%s 适配器不支持截图同步", providerDisplayName(item.Provider))
	}
	existing, _ := s.db.ListASMScreenshots(item.ID)
	existingBySource := make(map[string]*database.ASMScreenshot, len(existing))
	for _, screenshot := range existing {
		existingBySource[screenshot.SourceURL] = screenshot
	}
	for _, reference := range references {
		if cached := existingBySource[reference.URL]; cached != nil {
			if info, statErr := os.Stat(cached.FilePath); statErr == nil && info.Mode().IsRegular() {
				result.Skipped++
				continue
			}
		}
		data, contentType, fetchErr := fetcher.FetchScreenshot(ctx, conn, reference.URL)
		if fetchErr != nil {
			result.Errors = append(result.Errors, truncateError(fetchErr))
			continue
		}
		_, extension, typeErr := imageContentType(data)
		if typeErr != nil {
			result.Errors = append(result.Errors, truncateError(typeErr))
			continue
		}
		digest := sha256.Sum256(data)
		digestHex := hex.EncodeToString(digest[:])
		taskDir := filepath.Join(s.screenshotDir, item.ID)
		if mkErr := os.MkdirAll(taskDir, 0o750); mkErr != nil {
			result.Errors = append(result.Errors, truncateError(mkErr))
			continue
		}
		path := filepath.Join(taskDir, digestHex[:32]+extension)
		if writeErr := os.WriteFile(path, data, 0o600); writeErr != nil {
			result.Errors = append(result.Errors, truncateError(writeErr))
			continue
		}
		screenshot := &database.ASMScreenshot{
			ID:     "asmshot_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20],
			TaskID: item.ID, SourceURL: reference.URL, Label: reference.Label,
			FilePath: path, ContentType: contentType, SizeBytes: int64(len(data)), SHA256: digestHex,
		}
		if saveErr := s.db.UpsertASMScreenshot(screenshot); saveErr != nil {
			result.Errors = append(result.Errors, truncateError(saveErr))
			continue
		}
		result.Downloaded++
	}
	result.Screenshots, err = s.db.ListASMScreenshots(item.ID)
	result.Screenshots = enrichScreenshotURLs(result.Screenshots)
	return result, err
}

func (s *Service) screenshotSources(ctx context.Context, item *database.ASMTask) ([]interface{}, error) {
	conn, adapter, err := s.connection(item.ResourceID, false)
	if err != nil {
		return nil, err
	}
	resultTypes := []string{"site"}
	if normalizeProvider(item.Provider) == ProviderXingRin {
		resultTypes = []string{"screenshot", "site"}
	}
	payloads := make([]interface{}, 0, len(resultTypes))
	for _, resultType := range resultTypes {
		// Completed result localization already stores the normalized upstream
		// records. Prefer those records so opening the task center does not repeat
		// an expensive list request merely to discover screenshot paths.
		if rows, _, localErr := s.db.ListASMResultItems(item.ID, resultType, "", 1, 200); localErr == nil && len(rows) > 0 {
			local := make([]interface{}, 0, len(rows))
			for _, raw := range rows {
				var value interface{}
				if json.Unmarshal([]byte(raw), &value) == nil {
					local = append(local, value)
				}
			}
			if len(local) > 0 {
				payloads = append(payloads, map[string]interface{}{"results": local, "source": "local"})
				if len(collectScreenshotReferences(local)) > 0 {
					break
				}
			}
		}
		payload, listErr := adapter.ListAssets(ctx, conn, AssetFilter{TaskID: item.RemoteTaskID, Type: resultType, Page: 1, PageSize: 100})
		if listErr != nil {
			if len(payloads) == 0 {
				err = listErr
			}
			continue
		}
		payloads = append(payloads, payload)
		if len(collectScreenshotReferences(payload)) > 0 {
			break
		}
	}
	if len(payloads) == 0 {
		return nil, err
	}
	return payloads, nil
}

func (s *Service) SyncTaskScreenshots(ctx context.Context, id string) (ScreenshotSyncResult, error) {
	item, err := s.db.GetASMTask(id)
	if err != nil {
		return ScreenshotSyncResult{}, err
	}
	payloads, err := s.screenshotSources(ctx, item)
	if err != nil {
		return ScreenshotSyncResult{}, err
	}
	return s.cacheTaskScreenshotPayload(ctx, id, payloads)
}

func (s *Service) enqueueTaskScreenshotCache(id string, payload interface{}) {
	if len(collectScreenshotReferences(payload)) == 0 {
		return
	}
	s.screenshotMu.Lock()
	if s.screenshotJobs[id] {
		s.screenshotMu.Unlock()
		return
	}
	s.screenshotJobs[id] = true
	delete(s.screenshotErrors, id)
	s.screenshotMu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		result, err := s.cacheTaskScreenshotPayload(ctx, id, payload)
		if err == nil && len(result.Errors) > 0 {
			err = fmt.Errorf("%d 张 ASM 截图缓存失败: %s", len(result.Errors), strings.Join(result.Errors, "; "))
		}
		s.screenshotMu.Lock()
		delete(s.screenshotJobs, id)
		if err != nil {
			s.screenshotErrors[id] = truncateError(err)
		}
		s.screenshotMu.Unlock()
		if err != nil {
			s.logger.Warn("自动缓存 ASM 截图失败", zap.String("task_id", id), zap.Error(err))
		}
	}()
}

func (s *Service) ScreenshotCacheState(id string) (bool, string) {
	s.screenshotMu.Lock()
	defer s.screenshotMu.Unlock()
	return s.screenshotJobs[id], s.screenshotErrors[id]
}

func (s *Service) GetScreenshotFile(id string) (*database.ASMScreenshot, error) {
	item, err := s.db.GetASMScreenshot(id)
	if err != nil {
		return nil, err
	}
	base, err := filepath.Abs(s.screenshotDir)
	if err != nil {
		return nil, fmt.Errorf("解析截图根目录失败: %w", err)
	}
	path, err := filepath.Abs(item.FilePath)
	if err != nil {
		return nil, fmt.Errorf("解析截图路径失败: %w", err)
	}
	relative, err := filepath.Rel(base, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("截图路径超出允许目录")
	}
	if info, statErr := os.Stat(path); statErr != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("ASM 截图文件不存在")
	}
	item.FilePath = path
	return item, nil
}
