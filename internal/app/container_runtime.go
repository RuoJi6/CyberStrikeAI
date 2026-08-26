package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cyberstrike-ai/internal/boundary"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/egress"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const tlsAuthorityRotationPeriod = 6 * 24 * time.Hour

func setupConversationContainerRuntime(cfg *config.Config, db *database.DB, credentialCipher *egress.CredentialCipher, logger *zap.Logger) (*containerruntime.Initializer, *containerruntime.DockerManager, *containerruntime.LifecycleController, *containerruntime.OrphanScanner, *egress.SnapshotStore, *egress.UpstreamRouteStore, *egress.AuthProfilesStore, *egress.TLSAuthorityStore, error) {
	if cfg == nil || !cfg.Container.Enabled {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil
	}
	snapshotStore, err := egress.NewSnapshotStore(cfg.Container.EgressSnapshotDir)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, err
	}
	upstreamStore, err := egress.NewUpstreamRouteStore(filepath.Join(snapshotStore.Root(), "upstream-routes"))
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, err
	}
	authProfilesStore, err := egress.NewAuthProfilesStore(filepath.Join(snapshotStore.Root(), "auth-profiles"))
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, err
	}
	tlsAuthorityStore, err := egress.NewTLSAuthorityStore(filepath.Join(snapshotStore.Root(), "tls-authorities"))
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, err
	}
	manager, err := containerruntime.NewDockerManagerFromEnvironment(containerruntime.DockerManagerOptions{
		OwnerID:                strings.TrimSpace(cfg.Container.OwnerID),
		OperationTimeout:       time.Duration(cfg.Container.CreateTimeoutSeconds) * time.Second,
		EgressSnapshotRoot:     snapshotStore.Root(),
		EgressUpstreamRoot:     upstreamStore.Root(),
		EgressAuthProfilesRoot: authProfilesStore.Root(),
		EgressTLSAuthorityRoot: tlsAuthorityStore.Root(),
	})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, err
	}
	gatewaySpec := conversationEgressGatewaySpec(cfg)
	initializerStore := &boundarySnapshotInitializationStore{
		DB: db, SnapshotStore: snapshotStore, UpstreamStore: upstreamStore, AuthProfilesStore: authProfilesStore,
		TLSAuthorityStore: tlsAuthorityStore,
		CredentialCipher:  credentialCipher, EgressGateway: &gatewaySpec,
	}
	initializer, err := containerruntime.NewInitializer(manager, initializerStore, containerruntime.InitializerOptions{
		Workers:       cfg.Container.InitializerWorkers,
		QueueCapacity: cfg.Container.QueueCapacity,
		CreateTimeout: time.Duration(cfg.Container.CreateTimeoutSeconds) * time.Second,
	})
	if err != nil {
		_ = manager.Close()
		return nil, nil, nil, nil, nil, nil, nil, nil, err
	}
	controller, err := containerruntime.NewLifecycleControllerWithOptions(manager, db, containerruntime.LifecycleControllerOptions{
		EgressGateway: &gatewaySpec,
		BoundarySnapshots: &boundarySnapshotRuntimeProvider{
			DB: db, SnapshotStore: snapshotStore, AuthProfilesStore: authProfilesStore, CredentialCipher: credentialCipher,
		},
		AuthProfiles: &boundarySnapshotRuntimeProvider{
			DB: db, SnapshotStore: snapshotStore, AuthProfilesStore: authProfilesStore, TLSAuthorityStore: tlsAuthorityStore, CredentialCipher: credentialCipher,
		},
		TLSAuthorities: &boundarySnapshotRuntimeProvider{
			DB: db, SnapshotStore: snapshotStore, AuthProfilesStore: authProfilesStore, TLSAuthorityStore: tlsAuthorityStore, CredentialCipher: credentialCipher,
		},
	})
	if err != nil {
		_ = initializer.Close(context.Background())
		_ = manager.Close()
		return nil, nil, nil, nil, nil, nil, nil, nil, err
	}
	orphanScanner, err := containerruntime.NewOrphanScanner(manager, db, containerruntime.OrphanScannerOptions{})
	if err != nil {
		_ = initializer.Close(context.Background())
		_ = manager.Close()
		return nil, nil, nil, nil, nil, nil, nil, nil, err
	}
	migrationCtx, migrationCancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = db.EnsureContainerRuntimeBoundarySnapshots(migrationCtx)
	migrationCancel()
	if err != nil {
		_ = initializer.Close(context.Background())
		_ = manager.Close()
		return nil, nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("bind boundary snapshots for durable container runtimes: %w", err)
	}
	egressMigrationCtx, egressMigrationCancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = db.EnsureContainerRuntimeEgressBindings(egressMigrationCtx)
	egressMigrationCancel()
	if err != nil {
		_ = initializer.Close(context.Background())
		_ = manager.Close()
		return nil, nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("bind upstream egress for durable container runtimes: %w", err)
	}
	rebuildRecoveryCtx, rebuildRecoveryCancel := context.WithTimeout(context.Background(), 10*time.Second)
	interruptedBoundaryRebuilds, err := db.MarkPendingConversationBoundaryRebuildsInterrupted(rebuildRecoveryCtx)
	rebuildRecoveryCancel()
	if err != nil {
		_ = initializer.Close(context.Background())
		_ = manager.Close()
		return nil, nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("inspect interrupted boundary rebuilds: %w", err)
	}
	if interruptedBoundaryRebuilds > 0 {
		logger.Warn("检测到服务重启中断的边界快照重建请求；执行将失败关闭直到显式重试",
			zap.Int64("count", interruptedBoundaryRebuilds))
	}
	egressRebuildRecoveryCtx, egressRebuildRecoveryCancel := context.WithTimeout(context.Background(), 10*time.Second)
	interruptedEgressRebuilds, err := db.MarkPendingConversationEgressRebuildsInterrupted(egressRebuildRecoveryCtx)
	egressRebuildRecoveryCancel()
	if err != nil {
		_ = initializer.Close(context.Background())
		_ = manager.Close()
		return nil, nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("inspect interrupted upstream egress rebuilds: %w", err)
	}
	if interruptedEgressRebuilds > 0 {
		logger.Warn("检测到服务重启中断的上游出口重建请求；保留当前生效出口直到显式重试",
			zap.Int64("count", interruptedEgressRebuilds))
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
	return initializer, manager, controller, orphanScanner, snapshotStore, upstreamStore, authProfilesStore, tlsAuthorityStore, nil
}

// boundarySnapshotInitializationStore is the final fail-closed guard before a
// worker claims durable initialization work. It also covers queued work resumed
// during process startup, which does not pass through the chat scheduler.
type boundarySnapshotInitializationStore struct {
	*database.DB
	SnapshotStore     *egress.SnapshotStore
	UpstreamStore     *egress.UpstreamRouteStore
	AuthProfilesStore *egress.AuthProfilesStore
	TLSAuthorityStore *egress.TLSAuthorityStore
	CredentialCipher  *egress.CredentialCipher
	EgressGateway     *containerruntime.EgressGatewaySpec
}

func (s *boundarySnapshotInitializationStore) Claim(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, bool, error) {
	if s == nil || s.DB == nil {
		return containerruntime.InitializationRecord{}, false, fmt.Errorf("boundary snapshot initialization store is not configured")
	}
	binding, err := s.DB.EnsureConversationEgressBinding(ctx, conversationID)
	if err != nil {
		return containerruntime.InitializationRecord{}, false, fmt.Errorf("bind conversation upstream egress before runtime claim: %w", err)
	}
	upstreamRoute, err := materializeConversationUpstreamRoute(ctx, s.DB, s.CredentialCipher, s.UpstreamStore, binding)
	if err != nil {
		return containerruntime.InitializationRecord{}, false, fmt.Errorf("materialize conversation upstream egress before runtime claim: %w", err)
	}
	snapshot, err := s.DB.EnsureConversationBoundarySnapshot(ctx, conversationID)
	if err != nil {
		return containerruntime.InitializationRecord{}, false, fmt.Errorf("bind conversation boundary snapshot before runtime claim: %w", err)
	}
	snapshotSpec, err := materializeBoundarySnapshot(s.SnapshotStore, snapshot)
	if err != nil {
		return containerruntime.InitializationRecord{}, false, fmt.Errorf("materialize conversation boundary snapshot before runtime claim: %w", err)
	}
	authProfiles, err := materializeConversationAuthProfiles(ctx, s.DB, s.CredentialCipher, s.AuthProfilesStore, snapshot)
	if err != nil {
		return containerruntime.InitializationRecord{}, false, fmt.Errorf("materialize conversation auth profiles before runtime claim: %w", err)
	}
	tlsAuthority, err := materializeConversationTLSAuthority(s.TLSAuthorityStore, snapshot)
	if err != nil {
		return containerruntime.InitializationRecord{}, false, fmt.Errorf("materialize conversation TLS authority before runtime claim: %w", err)
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
			gateway.UpstreamRoute = upstreamRoute
			gateway.AuthProfiles = authProfiles
			gateway.TLSAuthority = tlsAuthority
			target.EgressGateway = &gateway
		} else if target.EgressGateway != nil {
			gateway := *target.EgressGateway
			gateway.BoundarySnapshot = &snapshotSpec
			gateway.UpstreamRoute = upstreamRoute
			gateway.AuthProfiles = authProfiles
			gateway.TLSAuthority = tlsAuthority
			target.EgressGateway = &gateway
		}
		if _, err := s.DB.UpgradeQueuedContainerRuntimeTopology(ctx, conversationID, target); err != nil {
			return containerruntime.InitializationRecord{}, false, fmt.Errorf("upgrade queued runtime boundary snapshot before claim: %w", err)
		}
	}
	return s.DB.Claim(ctx, conversationID)
}

type boundarySnapshotRuntimeProvider struct {
	DB                *database.DB
	SnapshotStore     *egress.SnapshotStore
	AuthProfilesStore *egress.AuthProfilesStore
	TLSAuthorityStore *egress.TLSAuthorityStore
	CredentialCipher  *egress.CredentialCipher
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

func (p *boundarySnapshotRuntimeProvider) ResolveAuthProfiles(ctx context.Context, conversationID, snapshotID string) (*containerruntime.EgressAuthProfilesSpec, error) {
	if p == nil || p.DB == nil || p.AuthProfilesStore == nil {
		return nil, fmt.Errorf("auth profiles provider is not configured")
	}
	var snapshot database.ConversationBoundarySnapshot
	var err error
	if strings.TrimSpace(snapshotID) == "" {
		snapshot, err = p.DB.GetConversationBoundarySnapshot(ctx, conversationID)
	} else {
		snapshot, err = p.DB.GetPendingConversationBoundarySnapshot(ctx, conversationID, snapshotID)
	}
	if err != nil {
		return nil, err
	}
	return materializeConversationAuthProfiles(ctx, p.DB, p.CredentialCipher, p.AuthProfilesStore, snapshot)
}

func (p *boundarySnapshotRuntimeProvider) ResolveTLSAuthority(ctx context.Context, conversationID, snapshotID string) (*containerruntime.EgressTLSAuthoritySpec, error) {
	if p == nil || p.DB == nil || p.TLSAuthorityStore == nil {
		return nil, fmt.Errorf("TLS authority provider is not configured")
	}
	var snapshot database.ConversationBoundarySnapshot
	var err error
	if strings.TrimSpace(snapshotID) == "" {
		snapshot, err = p.DB.GetConversationBoundarySnapshot(ctx, conversationID)
	} else {
		snapshot, err = p.DB.GetPendingConversationBoundarySnapshot(ctx, conversationID, snapshotID)
	}
	if err != nil {
		return nil, err
	}
	return materializeConversationTLSAuthority(p.TLSAuthorityStore, snapshot)
}

func materializeConversationTLSAuthority(store *egress.TLSAuthorityStore, snapshot database.ConversationBoundarySnapshot) (*containerruntime.EgressTLSAuthoritySpec, error) {
	return materializeConversationTLSAuthorityAt(store, snapshot, time.Now().UTC())
}

func materializeConversationTLSAuthorityAt(store *egress.TLSAuthorityStore, snapshot database.ConversationBoundarySnapshot, now time.Time) (*containerruntime.EgressTLSAuthoritySpec, error) {
	if snapshot.Document.TLSInspection == nil || !snapshot.Document.TLSInspection.Enabled {
		return nil, nil
	}
	if store == nil {
		return nil, fmt.Errorf("TLS authority store is not configured")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	rotationBucket := now.Unix() / int64(tlsAuthorityRotationPeriod/time.Second)
	authorityID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(snapshot.SnapshotID+":"+fmt.Sprint(rotationBucket))).String()
	authority, err := egress.GenerateTLSAuthority(snapshot.ConversationID, now, 7*24*time.Hour)
	if err != nil {
		return nil, err
	}
	reference, _, _, err := store.Put(authorityID, authority)
	if err != nil {
		return nil, err
	}
	return &containerruntime.EgressTLSAuthoritySpec{
		ID: reference.ID, BoundarySnapshotID: snapshot.SnapshotID,
		CertificateSHA256: reference.CertificateSHA256, PrivateKeySHA256: reference.PrivateKeySHA256,
	}, nil
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

func materializeConversationAuthProfiles(ctx context.Context, db *database.DB, cipher *egress.CredentialCipher, store *egress.AuthProfilesStore, snapshot database.ConversationBoundarySnapshot) (*containerruntime.EgressAuthProfilesSpec, error) {
	required := make(map[string]struct{})
	for _, rule := range snapshot.Document.Rules {
		if rule.Effect == boundary.EffectAuthOnly && rule.AuthProfileID != nil {
			required[*rule.AuthProfileID] = struct{}{}
		}
	}
	if len(required) == 0 {
		return nil, nil
	}
	if db == nil || cipher == nil || store == nil {
		return nil, fmt.Errorf("egress auth profile materializer is not configured")
	}
	ids := make([]string, 0, len(required))
	for id := range required {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	profiles := make([]egress.GatewayAuthProfile, 0, len(ids))
	saltHash := sha256.New()
	versionHash := sha256.New()
	for _, id := range ids {
		profile, err := db.GetEgressAuthProfile(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("load auth profile %s: %w", id, err)
		}
		if !profile.Enabled || !profile.CredentialsConfigured || strings.TrimSpace(profile.CredentialCiphertext) == "" {
			return nil, fmt.Errorf("auth profile %s is disabled or has no credential", id)
		}
		plaintext, err := cipher.DecryptAuthProfile(profile.ID, profile.CredentialCiphertext)
		if err != nil {
			return nil, fmt.Errorf("decrypt auth profile %s credential: %w", id, err)
		}
		value := string(plaintext)
		clear(plaintext)
		if err := egress.ValidateAuthHeaderValue(value); err != nil {
			return nil, fmt.Errorf("decode auth profile %s credential: %w", id, err)
		}
		profiles = append(profiles, egress.GatewayAuthProfile{ID: profile.ID, HeaderName: profile.HeaderName, HeaderValue: value})
		_, _ = saltHash.Write([]byte(profile.ID + "\x00" + profile.CredentialCiphertext + "\x00"))
		_, _ = versionHash.Write([]byte(profile.ID + "\x00" + profile.HeaderName + "\x00" + profile.UpdatedAt.UTC().Format(time.RFC3339Nano) + "\x00"))
	}
	document := egress.NewAuthProfilesDocument(hex.EncodeToString(saltHash.Sum(nil)), profiles)
	version := hex.EncodeToString(versionHash.Sum(nil))[:16]
	id := "auth-" + snapshot.SnapshotID + "-" + version
	reference, _, err := store.Put(id, document)
	if err != nil {
		return nil, err
	}
	return &containerruntime.EgressAuthProfilesSpec{ID: reference.ID, SHA256: reference.SHA256}, nil
}

func materializeConversationUpstreamRoute(ctx context.Context, db *database.DB, cipher *egress.CredentialCipher, store *egress.UpstreamRouteStore, binding database.ConversationEgressBinding) (*containerruntime.EgressUpstreamRouteSpec, error) {
	return materializeConversationUpstreamRouteWithID(ctx, db, cipher, store, binding, binding.ConversationID)
}

func materializeConversationUpstreamRouteWithID(ctx context.Context, db *database.DB, cipher *egress.CredentialCipher, store *egress.UpstreamRouteStore, binding database.ConversationEgressBinding, routeID string) (*containerruntime.EgressUpstreamRouteSpec, error) {
	if binding.Mode == database.ConversationEgressModeNone {
		return nil, nil
	}
	if db == nil || store == nil {
		return nil, fmt.Errorf("egress upstream route materializer is not configured")
	}
	var route egress.UpstreamRoute
	switch binding.Mode {
	case database.ConversationEgressModeProxy:
		if binding.Proxy == nil {
			return nil, database.ErrConversationEgressIntegrity
		}
		proxy, err := db.GetEgressProxy(ctx, binding.Proxy.ID)
		if err != nil {
			return nil, err
		}
		if !proxy.Enabled {
			return nil, database.ErrNoAvailableEgressProxy
		}
		endpoint, err := materializeUpstreamEndpoint(cipher, proxy)
		if err != nil {
			return nil, err
		}
		route = egress.NewProxyUpstreamRoute(endpoint)
	case database.ConversationEgressModeGroup:
		if binding.ProxyGroup == nil {
			return nil, database.ErrConversationEgressIntegrity
		}
		group, err := db.GetEgressProxyGroup(ctx, binding.ProxyGroup.ID)
		if err != nil {
			return nil, err
		}
		if !group.Enabled || !group.FailClosed {
			return nil, database.ErrNoAvailableEgressProxy
		}
		routeGroup := egress.UpstreamRouteGroup{
			ID: group.ID, FailureThreshold: group.FailureThreshold, CooldownSeconds: group.CooldownSeconds,
			Members: make([]egress.UpstreamRouteMember, 0, len(group.Members)),
		}
		for _, member := range group.Members {
			if !member.Enabled || !member.Proxy.Enabled {
				continue
			}
			proxy, err := db.GetEgressProxy(ctx, member.ProxyID)
			if err != nil {
				return nil, err
			}
			if !proxy.Enabled {
				continue
			}
			endpoint, err := materializeUpstreamEndpoint(cipher, proxy)
			if err != nil {
				return nil, err
			}
			routeGroup.Members = append(routeGroup.Members, egress.UpstreamRouteMember{
				Proxy: endpoint, Priority: member.Priority, Weight: member.Weight,
			})
		}
		if len(routeGroup.Members) == 0 {
			return nil, database.ErrNoAvailableEgressProxy
		}
		route = egress.NewProxyGroupUpstreamRoute(routeGroup)
	default:
		return nil, database.ErrConversationEgressIntegrity
	}
	reference, _, err := store.Put(strings.TrimSpace(routeID), route)
	if err != nil {
		return nil, err
	}
	return &containerruntime.EgressUpstreamRouteSpec{ID: reference.ID, SHA256: reference.SHA256}, nil
}

func materializeUpstreamEndpoint(cipher *egress.CredentialCipher, proxy database.EgressProxy) (egress.UpstreamEndpoint, error) {
	endpoint := egress.UpstreamEndpoint{
		ID: proxy.ID, Protocol: proxy.Protocol, Host: proxy.Host, Port: proxy.Port,
	}
	if strings.TrimSpace(proxy.CredentialCiphertext) == "" {
		return endpoint, nil
	}
	if cipher == nil {
		return egress.UpstreamEndpoint{}, fmt.Errorf("egress credential cipher is not configured")
	}
	plaintext, err := cipher.Decrypt(proxy.ID, proxy.CredentialCiphertext)
	if err != nil {
		return egress.UpstreamEndpoint{}, fmt.Errorf("decrypt egress proxy %s credentials: %w", proxy.ID, err)
	}
	defer clear(plaintext)
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	var credentials egress.ProxyCredentials
	if err := decoder.Decode(&credentials); err != nil {
		return egress.UpstreamEndpoint{}, fmt.Errorf("decode egress proxy %s credentials", proxy.ID)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return egress.UpstreamEndpoint{}, fmt.Errorf("decode egress proxy %s credentials", proxy.ID)
	}
	if strings.TrimSpace(credentials.Username) == "" {
		return egress.UpstreamEndpoint{}, fmt.Errorf("egress proxy %s credential username is invalid", proxy.ID)
	}
	endpoint.Username = credentials.Username
	endpoint.Password = credentials.Password
	return endpoint, nil
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
func conversationContainerSpec(cfg *config.Config, conversationID string, workspacePersistent bool, snapshot containerruntime.EgressBoundarySnapshotSpec, upstreamRoute *containerruntime.EgressUpstreamRouteSpec, authProfiles *containerruntime.EgressAuthProfilesSpec, tlsAuthority *containerruntime.EgressTLSAuthoritySpec) (containerruntime.RuntimeSpec, error) {
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
			gateway.UpstreamRoute = upstreamRoute
			gateway.AuthProfiles = authProfiles
			gateway.TLSAuthority = tlsAuthority
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

func applyConversationRuntimeControls(spec *containerruntime.RuntimeSpec, controls database.ConversationRuntimeControls) {
	if spec == nil {
		return
	}
	if controls.CustomResourcesEnabled {
		spec.Resources.NanoCPUs = controls.NanoCPUs
		spec.Resources.MemoryBytes = controls.MemoryBytes
	}
	if spec.EgressGateway != nil && controls.ScanRateEnabled {
		gateway := *spec.EgressGateway
		gateway.TrafficLimits = &containerruntime.EgressTrafficLimits{
			HTTPRequestsPerSecond:   controls.HTTPRequestsPerSecond,
			TCPConnectionsPerSecond: controls.TCPConnectionsPerSecond,
			UDPDatagramsPerSecond:   controls.UDPDatagramsPerSecond,
		}
		spec.EgressGateway = &gateway
	}
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
