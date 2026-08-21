package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/egress"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"go.uber.org/zap"
)

func setupConversationContainerRuntime(cfg *config.Config, db *database.DB, logger *zap.Logger) (*containerruntime.Initializer, *containerruntime.DockerManager, *containerruntime.LifecycleController, *containerruntime.OrphanScanner, *egress.SnapshotStore, error) {
	if cfg == nil || !cfg.Container.Enabled {
		return nil, nil, nil, nil, nil, nil
	}
	snapshotStore, err := egress.NewSnapshotStore(cfg.Container.EgressSnapshotDir)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	manager, err := containerruntime.NewDockerManagerFromEnvironment(containerruntime.DockerManagerOptions{
		OwnerID:            strings.TrimSpace(cfg.Container.OwnerID),
		OperationTimeout:   time.Duration(cfg.Container.CreateTimeoutSeconds) * time.Second,
		EgressSnapshotRoot: snapshotStore.Root(),
	})
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	gatewaySpec := conversationEgressGatewaySpec(cfg)
	initializerStore := &boundarySnapshotInitializationStore{
		DB: db, SnapshotStore: snapshotStore, EgressGateway: &gatewaySpec,
	}
	initializer, err := containerruntime.NewInitializer(manager, initializerStore, containerruntime.InitializerOptions{
		Workers:       cfg.Container.InitializerWorkers,
		QueueCapacity: cfg.Container.QueueCapacity,
		CreateTimeout: time.Duration(cfg.Container.CreateTimeoutSeconds) * time.Second,
	})
	if err != nil {
		_ = manager.Close()
		return nil, nil, nil, nil, nil, err
	}
	controller, err := containerruntime.NewLifecycleControllerWithOptions(manager, db, containerruntime.LifecycleControllerOptions{
		EgressGateway:     &gatewaySpec,
		BoundarySnapshots: &boundarySnapshotRuntimeProvider{DB: db, SnapshotStore: snapshotStore},
	})
	if err != nil {
		_ = initializer.Close(context.Background())
		_ = manager.Close()
		return nil, nil, nil, nil, nil, err
	}
	orphanScanner, err := containerruntime.NewOrphanScanner(manager, db, containerruntime.OrphanScannerOptions{})
	if err != nil {
		_ = initializer.Close(context.Background())
		_ = manager.Close()
		return nil, nil, nil, nil, nil, err
	}
	migrationCtx, migrationCancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = db.EnsureContainerRuntimeBoundarySnapshots(migrationCtx)
	migrationCancel()
	if err != nil {
		_ = initializer.Close(context.Background())
		_ = manager.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("bind boundary snapshots for durable container runtimes: %w", err)
	}
	rebuildRecoveryCtx, rebuildRecoveryCancel := context.WithTimeout(context.Background(), 10*time.Second)
	interruptedBoundaryRebuilds, err := db.MarkPendingConversationBoundaryRebuildsInterrupted(rebuildRecoveryCtx)
	rebuildRecoveryCancel()
	if err != nil {
		_ = initializer.Close(context.Background())
		_ = manager.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("inspect interrupted boundary rebuilds: %w", err)
	}
	if interruptedBoundaryRebuilds > 0 {
		logger.Warn("检测到服务重启中断的边界快照重建请求；执行将失败关闭直到显式重试",
			zap.Int64("count", interruptedBoundaryRebuilds))
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
		zap.String("egressImageRepository", cfg.Container.EgressImageRepository),
		zap.String("egressImageDigest", cfg.Container.EgressImageDigest),
		zap.String("egressImagePlatform", cfg.Container.EgressImagePlatform),
		zap.String("toolInventoryDigest", cfg.Container.ToolInventoryDigest),
		zap.Int("toolCount", len(cfg.Container.ToolInventory.Tools)),
	)
	return initializer, manager, controller, orphanScanner, snapshotStore, nil
}

// boundarySnapshotInitializationStore is the final fail-closed guard before a
// worker claims durable initialization work. It also covers queued work resumed
// during process startup, which does not pass through the chat scheduler.
type boundarySnapshotInitializationStore struct {
	*database.DB
	SnapshotStore *egress.SnapshotStore
	EgressGateway *containerruntime.EgressGatewaySpec
}

func (s *boundarySnapshotInitializationStore) Claim(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, bool, error) {
	if s == nil || s.DB == nil {
		return containerruntime.InitializationRecord{}, false, fmt.Errorf("boundary snapshot initialization store is not configured")
	}
	snapshot, err := s.DB.EnsureConversationBoundarySnapshot(ctx, conversationID)
	if err != nil {
		return containerruntime.InitializationRecord{}, false, fmt.Errorf("bind conversation boundary snapshot before runtime claim: %w", err)
	}
	snapshotSpec, err := materializeBoundarySnapshot(s.SnapshotStore, snapshot)
	if err != nil {
		return containerruntime.InitializationRecord{}, false, fmt.Errorf("materialize conversation boundary snapshot before runtime claim: %w", err)
	}
	record, err := s.DB.GetContainerInitialization(ctx, conversationID)
	if err != nil {
		return containerruntime.InitializationRecord{}, false, err
	}
	if record.Status == containerruntime.InitializationQueued {
		target := record.Spec
		if target.Security.NetworkMode == containerruntime.NetworkNone {
			target.Security.NetworkMode = containerruntime.NetworkInternal
		}
		if s.EgressGateway != nil {
			gateway := *s.EgressGateway
			gateway.BoundarySnapshot = &snapshotSpec
			target.EgressGateway = &gateway
		} else if target.EgressGateway != nil {
			gateway := *target.EgressGateway
			gateway.BoundarySnapshot = &snapshotSpec
			target.EgressGateway = &gateway
		}
		if _, err := s.DB.UpgradeQueuedContainerRuntimeTopology(ctx, conversationID, target); err != nil {
			return containerruntime.InitializationRecord{}, false, fmt.Errorf("upgrade queued runtime boundary snapshot before claim: %w", err)
		}
	}
	return s.DB.Claim(ctx, conversationID)
}

type boundarySnapshotRuntimeProvider struct {
	DB            *database.DB
	SnapshotStore *egress.SnapshotStore
}

func (p *boundarySnapshotRuntimeProvider) ResolveBoundarySnapshot(ctx context.Context, conversationID, snapshotID string) (containerruntime.EgressBoundarySnapshotSpec, error) {
	if p == nil || p.DB == nil || p.SnapshotStore == nil {
		return containerruntime.EgressBoundarySnapshotSpec{}, fmt.Errorf("boundary snapshot provider is not configured")
	}
	var snapshot database.ConversationBoundarySnapshot
	var err error
	if strings.TrimSpace(snapshotID) == "" {
		snapshot, err = p.DB.GetConversationBoundarySnapshot(ctx, conversationID)
	} else {
		snapshot, err = p.DB.GetPendingConversationBoundarySnapshot(ctx, conversationID, snapshotID)
	}
	if err != nil {
		return containerruntime.EgressBoundarySnapshotSpec{}, err
	}
	return materializeBoundarySnapshot(p.SnapshotStore, snapshot)
}

func materializeBoundarySnapshot(store *egress.SnapshotStore, snapshot database.ConversationBoundarySnapshot) (containerruntime.EgressBoundarySnapshotSpec, error) {
	if store == nil {
		return containerruntime.EgressBoundarySnapshotSpec{}, fmt.Errorf("egress snapshot store is not configured")
	}
	reference := egress.SnapshotReference{ID: snapshot.SnapshotID, SHA256: snapshot.SHA256}
	if _, err := store.Put(reference, snapshot.CanonicalJSON); err != nil {
		return containerruntime.EgressBoundarySnapshotSpec{}, err
	}
	return containerruntime.EgressBoundarySnapshotSpec{ID: reference.ID, SHA256: reference.SHA256}, nil
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

func logContainerIdleStop(logger *zap.Logger, report containerruntime.IdleStopReport, err error) {
	fields := []zap.Field{
		zap.Int("candidates", report.Candidates), zap.Int("activeTasks", report.ActiveTasks),
		zap.Int("stopped", report.Stopped), zap.Int("skipped", report.Skipped), zap.Int("failed", report.Failed),
	}
	if err != nil {
		logger.Warn("空闲对话容器自动停止未全部成功", append(fields, zap.Error(err))...)
		return
	}
	if report.Candidates > 0 {
		logger.Info("空闲对话容器自动停止扫描完成", fields...)
	}
}

// conversationContainerSpec converts trusted configuration into the immutable
// specification used when phase 2 requests a container for first execution.
func conversationContainerSpec(cfg *config.Config, conversationID string, workspacePersistent bool, snapshot containerruntime.EgressBoundarySnapshotSpec) (containerruntime.RuntimeSpec, error) {
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
			NetworkMode:         containerruntime.NetworkInternal,
			SeccompProfile:      "default",
			TmpfsBytes:          cfg.Container.TmpfsBytes,
		},
		Workspace: containerruntime.WorkspaceSpec{
			Persistent: workspacePersistent,
			MountPath:  "/workspace",
		},
		Readiness: containerruntime.ReadinessPolicy{
			Enabled:         true,
			InventoryDigest: strings.TrimSpace(cfg.Container.ToolInventoryDigest),
			Inventory:       cfg.Container.ToolInventory,
		},
		EgressGateway: func() *containerruntime.EgressGatewaySpec {
			gateway := conversationEgressGatewaySpec(cfg)
			gateway.BoundarySnapshot = &snapshot
			return &gateway
		}(),
	}
	if workspacePersistent {
		spec.Workspace.VolumeName = containerruntime.WorkspaceVolumeName(spec.ID)
	}
	if err := containerruntime.ValidateSpec(spec); err != nil {
		return containerruntime.RuntimeSpec{}, err
	}
	return spec, nil
}

func conversationEgressGatewaySpec(cfg *config.Config) containerruntime.EgressGatewaySpec {
	return containerruntime.EgressGatewaySpec{
		Image: containerruntime.ImageReference{
			Repository: strings.TrimSpace(cfg.Container.EgressImageRepository),
			Digest:     strings.TrimSpace(cfg.Container.EgressImageDigest),
			Platform:   strings.TrimSpace(cfg.Container.EgressImagePlatform),
		},
		Resources: containerruntime.EgressGatewayResources{
			NanoCPUs:    cfg.Container.EgressNanoCPUs,
			MemoryBytes: cfg.Container.EgressMemoryBytes,
			PIDs:        cfg.Container.EgressPIDs,
			NoFileSoft:  cfg.Container.EgressNoFileSoft,
			NoFileHard:  cfg.Container.EgressNoFileHard,
			TmpfsBytes:  cfg.Container.EgressTmpfsBytes,
			LogMaxBytes: cfg.Container.EgressLogMaxBytes,
			LogMaxFiles: cfg.Container.EgressLogMaxFiles,
		},
	}
}
