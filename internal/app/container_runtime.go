package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"go.uber.org/zap"
)

func setupConversationContainerRuntime(cfg *config.Config, db *database.DB, logger *zap.Logger) (*containerruntime.Initializer, *containerruntime.DockerManager, error) {
	if cfg == nil || !cfg.Container.Enabled {
		return nil, nil, nil
	}
	manager, err := containerruntime.NewDockerManagerFromEnvironment(containerruntime.DockerManagerOptions{
		OwnerID:          strings.TrimSpace(cfg.Container.OwnerID),
		OperationTimeout: time.Duration(cfg.Container.CreateTimeoutSeconds) * time.Second,
	})
	if err != nil {
		return nil, nil, err
	}
	initializer, err := containerruntime.NewInitializer(manager, db, containerruntime.InitializerOptions{
		Workers:       cfg.Container.InitializerWorkers,
		QueueCapacity: cfg.Container.QueueCapacity,
		CreateTimeout: time.Duration(cfg.Container.CreateTimeoutSeconds) * time.Second,
	})
	if err != nil {
		_ = manager.Close()
		return nil, nil, err
	}
	recoverCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = initializer.Recover(recoverCtx)
	cancel()
	if err != nil {
		logger.Warn("恢复容器后台初始化任务未全部成功", zap.Error(err))
	}
	logger.Info("对话容器后台初始化器已启用",
		zap.Int("workers", cfg.Container.InitializerWorkers),
		zap.Int("queueCapacity", cfg.Container.QueueCapacity),
		zap.String("imageRepository", cfg.Container.ImageRepository),
		zap.String("imageDigest", cfg.Container.ImageDigest),
		zap.String("imagePlatform", cfg.Container.ImagePlatform),
	)
	return initializer, manager, nil
}

// conversationContainerSpec converts trusted configuration into the immutable
// specification used when phase 2 requests a container for first execution.
func conversationContainerSpec(cfg *config.Config, conversationID string) (containerruntime.RuntimeSpec, error) {
	if cfg == nil || !cfg.Container.Enabled {
		return containerruntime.RuntimeSpec{}, fmt.Errorf("%w: conversation container runtime is disabled", containerruntime.ErrEngineUnavailable)
	}
	conversationID = strings.TrimSpace(conversationID)
	spec := containerruntime.RuntimeSpec{
		ID:             containerruntime.RuntimeID("conversation-" + conversationID),
		ConversationID: conversationID,
		Image: containerruntime.ImageReference{
			Repository: strings.TrimSpace(cfg.Container.ImageRepository),
			Digest:     strings.TrimSpace(cfg.Container.ImageDigest),
			Platform:   strings.TrimSpace(cfg.Container.ImagePlatform),
		},
		Resources: containerruntime.ResourceLimits{
			NanoCPUs:          cfg.Container.NanoCPUs,
			MemoryBytes:       cfg.Container.MemoryBytes,
			PIDs:              cfg.Container.PIDs,
			NoFileSoft:        cfg.Container.NoFileSoft,
			NoFileHard:        cfg.Container.NoFileHard,
			WorkspaceBytes:    cfg.Container.WorkspaceBytes,
			MaxConcurrentExec: cfg.Container.MaxConcurrentExec,
			MaxQueuedExec:     cfg.Container.MaxQueuedExec,
			LogMaxBytes:       cfg.Container.LogMaxBytes,
			LogMaxFiles:       cfg.Container.LogMaxFiles,
		},
		Security: containerruntime.SecurityProfile{
			ReadOnlyRootFS:      true,
			NoNewPrivileges:     true,
			DropAllCapabilities: true,
			NetworkMode:         containerruntime.NetworkNone,
			SeccompProfile:      "default",
			TmpfsBytes:          cfg.Container.TmpfsBytes,
		},
		Workspace: containerruntime.WorkspaceSpec{MountPath: "/workspace"},
	}
	if err := containerruntime.ValidateSpec(spec); err != nil {
		return containerruntime.RuntimeSpec{}, err
	}
	return spec, nil
}
