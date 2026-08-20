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

func setupConversationContainerRuntime(cfg *config.Config, db *database.DB, logger *zap.Logger) (*containerruntime.Initializer, *containerruntime.DockerManager, *containerruntime.LifecycleController, *containerruntime.OrphanScanner, error) {
	if cfg == nil || !cfg.Container.Enabled {
		return nil, nil, nil, nil, nil
	}
	manager, err := containerruntime.NewDockerManagerFromEnvironment(containerruntime.DockerManagerOptions{
		OwnerID:          strings.TrimSpace(cfg.Container.OwnerID),
		OperationTimeout: time.Duration(cfg.Container.CreateTimeoutSeconds) * time.Second,
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	initializer, err := containerruntime.NewInitializer(manager, db, containerruntime.InitializerOptions{
		Workers:       cfg.Container.InitializerWorkers,
		QueueCapacity: cfg.Container.QueueCapacity,
		CreateTimeout: time.Duration(cfg.Container.CreateTimeoutSeconds) * time.Second,
	})
	if err != nil {
		_ = manager.Close()
		return nil, nil, nil, nil, err
	}
	controller, err := containerruntime.NewLifecycleController(manager, db)
	if err != nil {
		_ = initializer.Close(context.Background())
		_ = manager.Close()
		return nil, nil, nil, nil, err
	}
	orphanScanner, err := containerruntime.NewOrphanScanner(manager, db, containerruntime.OrphanScannerOptions{})
	if err != nil {
		_ = initializer.Close(context.Background())
		_ = manager.Close()
		return nil, nil, nil, nil, err
	}
	recoverCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = initializer.Recover(recoverCtx)
	cancel()
	if err != nil {
		logger.Warn("恢复容器后台初始化任务未全部成功", zap.Error(err))
	}
	reconcileCtx, reconcileCancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = controller.Recover(reconcileCtx)
	reconcileCancel()
	if err != nil {
		logger.Warn("恢复并对账对话容器生命周期未全部成功", zap.Error(err))
	}
	orphanCtx, orphanCancel := context.WithTimeout(context.Background(), 30*time.Second)
	orphanReport, orphanErr := orphanScanner.Reconcile(orphanCtx)
	orphanCancel()
	logContainerOrphanScan(logger, orphanReport, orphanErr)
	logger.Info("对话容器后台初始化器已启用",
		zap.Int("workers", cfg.Container.InitializerWorkers),
		zap.Int("queueCapacity", cfg.Container.QueueCapacity),
		zap.String("imageRepository", cfg.Container.ImageRepository),
		zap.String("imageDigest", cfg.Container.ImageDigest),
		zap.String("imagePlatform", cfg.Container.ImagePlatform),
		zap.String("toolInventoryDigest", cfg.Container.ToolInventoryDigest),
		zap.Int("toolCount", len(cfg.Container.ToolInventory.Tools)),
	)
	return initializer, manager, controller, orphanScanner, nil
}

func logContainerOrphanScan(logger *zap.Logger, report containerruntime.OrphanScanReport, err error) {
	fields := []zap.Field{
		zap.Int("observed", report.Observed), zap.Int("retained", report.Retained),
		zap.Int("discovered", report.Discovered), zap.Int("attempted", report.Attempted),
		zap.Int("deleted", report.Deleted), zap.Int("missing", report.Missing), zap.Int("failed", report.Failed),
	}
	if err != nil {
		logger.Warn("对账所有者标签孤儿资源未全部成功", append(fields, zap.Error(err))...)
		return
	}
	if report.Discovered > 0 || report.Attempted > 0 {
		logger.Info("对账所有者标签孤儿资源完成", fields...)
	}
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
		Readiness: containerruntime.ReadinessPolicy{
			Enabled:         true,
			InventoryDigest: strings.TrimSpace(cfg.Container.ToolInventoryDigest),
			Inventory:       cfg.Container.ToolInventory,
		},
	}
	if err := containerruntime.ValidateSpec(spec); err != nil {
		return containerruntime.RuntimeSpec{}, err
	}
	return spec, nil
}
