package app

import (
	"os"
	"strings"

	"cyberstrike-ai/internal/traffictransform"

	"go.uber.org/zap"
)

const (
	trafficTransformRunnerURLEnv       = "CYBERSTRIKE_TRANSFORM_RUNNER_URL"
	trafficTransformRunnerTokenEnv     = "CYBERSTRIKE_TRANSFORM_RUNNER_TOKEN"
	trafficTransformRunnerTokenFileEnv = "CYBERSTRIKE_TRANSFORM_RUNNER_TOKEN_FILE"
)

func trafficTransformRunnerFromEnvironment(logger *zap.Logger) trafficTransformRunner {
	endpoint := strings.TrimSpace(os.Getenv(trafficTransformRunnerURLEnv))
	if endpoint == "" {
		return nil
	}
	token := strings.TrimSpace(os.Getenv(trafficTransformRunnerTokenEnv))
	if token == "" {
		path := strings.TrimSpace(os.Getenv(trafficTransformRunnerTokenFileEnv))
		if path != "" {
			info, err := os.Stat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
				if logger != nil {
					logger.Warn("Traffic Transform Runner token 文件不可用或权限不是 0600")
				}
				return nil
			}
			content, err := os.ReadFile(path)
			if err != nil {
				if logger != nil {
					logger.Warn("无法读取 Traffic Transform Runner token 文件", zap.Error(err))
				}
				return nil
			}
			token = strings.TrimSpace(string(content))
		}
	}
	client, err := traffictransform.NewHTTPClient(endpoint, token)
	if err != nil {
		if logger != nil {
			logger.Warn("Traffic Transform Runner 配置无效", zap.Error(err))
		}
		return nil
	}
	return client
}
