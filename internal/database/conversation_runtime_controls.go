package database

import (
	"context"
	"fmt"
	"time"
)

const (
	MinConversationNanoCPUs    int64 = 250_000_000
	MaxConversationNanoCPUs    int64 = 8_000_000_000
	MinConversationMemoryBytes int64 = 256 << 20
	MaxConversationMemoryBytes int64 = 16 << 30
	MaxConversationTrafficRate       = 100_000
)

// ConversationRuntimeControls are optional, user-selected limits for one
// Agent container. Disabled controls deliberately fall back to platform
// defaults instead of making the runtime unlimited.
type ConversationRuntimeControls struct {
	ScanRateEnabled         bool  `json:"scanRateEnabled"`
	HTTPRequestsPerSecond   int   `json:"httpRequestsPerSecond"`
	TCPConnectionsPerSecond int   `json:"tcpConnectionsPerSecond"`
	UDPDatagramsPerSecond   int   `json:"udpDatagramsPerSecond"`
	CustomResourcesEnabled  bool  `json:"customResourcesEnabled"`
	NanoCPUs                int64 `json:"nanoCpus"`
	MemoryBytes             int64 `json:"memoryBytes"`
}

func NormalizeConversationRuntimeControls(value ConversationRuntimeControls) (ConversationRuntimeControls, error) {
	if !value.ScanRateEnabled {
		value.HTTPRequestsPerSecond = 0
		value.TCPConnectionsPerSecond = 0
		value.UDPDatagramsPerSecond = 0
	} else {
		for name, rate := range map[string]int{
			"HTTP(S) 请求速率": value.HTTPRequestsPerSecond,
			"TCP 新连接速率":    value.TCPConnectionsPerSecond,
			"UDP 数据报速率":    value.UDPDatagramsPerSecond,
		} {
			if rate < 0 || rate > MaxConversationTrafficRate {
				return ConversationRuntimeControls{}, fmt.Errorf("%s 必须在 0 到 %d 之间", name, MaxConversationTrafficRate)
			}
		}
		if value.HTTPRequestsPerSecond == 0 && value.TCPConnectionsPerSecond == 0 && value.UDPDatagramsPerSecond == 0 {
			return ConversationRuntimeControls{}, fmt.Errorf("启用扫描速率限制后至少设置一个协议速率")
		}
	}
	if !value.CustomResourcesEnabled {
		value.NanoCPUs = 0
		value.MemoryBytes = 0
	} else {
		if value.NanoCPUs < MinConversationNanoCPUs || value.NanoCPUs > MaxConversationNanoCPUs {
			return ConversationRuntimeControls{}, fmt.Errorf("CPU 限额必须在 0.25 到 8 核之间")
		}
		if value.MemoryBytes < MinConversationMemoryBytes || value.MemoryBytes > MaxConversationMemoryBytes {
			return ConversationRuntimeControls{}, fmt.Errorf("内存限额必须在 256 MiB 到 16 GiB 之间")
		}
	}
	return value, nil
}

func (db *DB) initConversationRuntimeControlColumns() error {
	columns := []struct{ name, statement string }{
		{"scan_rate_enabled", "ALTER TABLE conversations ADD COLUMN scan_rate_enabled INTEGER NOT NULL DEFAULT 0 CHECK (scan_rate_enabled IN (0, 1))"},
		{"scan_http_rps", "ALTER TABLE conversations ADD COLUMN scan_http_rps INTEGER NOT NULL DEFAULT 0"},
		{"scan_tcp_cps", "ALTER TABLE conversations ADD COLUMN scan_tcp_cps INTEGER NOT NULL DEFAULT 0"},
		{"scan_udp_dps", "ALTER TABLE conversations ADD COLUMN scan_udp_dps INTEGER NOT NULL DEFAULT 0"},
		{"custom_resources_enabled", "ALTER TABLE conversations ADD COLUMN custom_resources_enabled INTEGER NOT NULL DEFAULT 0 CHECK (custom_resources_enabled IN (0, 1))"},
		{"custom_nano_cpus", "ALTER TABLE conversations ADD COLUMN custom_nano_cpus INTEGER NOT NULL DEFAULT 0"},
		{"custom_memory_bytes", "ALTER TABLE conversations ADD COLUMN custom_memory_bytes INTEGER NOT NULL DEFAULT 0"},
	}
	for _, column := range columns {
		if err := db.addColumnIfMissing("conversations", column.name, column.statement); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) GetConversationRuntimeControls(ctx context.Context, conversationID string) (ConversationRuntimeControls, error) {
	var value ConversationRuntimeControls
	err := db.QueryRowContext(ctx, `
		SELECT scan_rate_enabled, scan_http_rps, scan_tcp_cps, scan_udp_dps,
		       custom_resources_enabled, custom_nano_cpus, custom_memory_bytes
		FROM conversations WHERE id = ?
	`, conversationID).Scan(&value.ScanRateEnabled, &value.HTTPRequestsPerSecond, &value.TCPConnectionsPerSecond,
		&value.UDPDatagramsPerSecond, &value.CustomResourcesEnabled, &value.NanoCPUs, &value.MemoryBytes)
	return value, err
}

func (db *DB) SetConversationRuntimeControls(ctx context.Context, conversationID string, requested ConversationRuntimeControls) (ConversationRuntimeControls, error) {
	value, err := NormalizeConversationRuntimeControls(requested)
	if err != nil {
		return ConversationRuntimeControls{}, err
	}
	result, err := db.ExecContext(ctx, `
		UPDATE conversations SET
			scan_rate_enabled = ?, scan_http_rps = ?, scan_tcp_cps = ?, scan_udp_dps = ?,
			custom_resources_enabled = ?, custom_nano_cpus = ?, custom_memory_bytes = ?, updated_at = ?
		WHERE id = ? AND runtime_mode = 'container'
	`, value.ScanRateEnabled, value.HTTPRequestsPerSecond, value.TCPConnectionsPerSecond, value.UDPDatagramsPerSecond,
		value.CustomResourcesEnabled, value.NanoCPUs, value.MemoryBytes, formatSQLiteUTC(time.Now().UTC()), conversationID)
	if err != nil {
		return ConversationRuntimeControls{}, fmt.Errorf("保存容器运行控制失败: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return ConversationRuntimeControls{}, fmt.Errorf("container conversation not found")
	}
	return value, nil
}
