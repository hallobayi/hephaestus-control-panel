package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go-hephaestus/internal/config"
	"go-hephaestus/internal/core/domain"
	"go-hephaestus/internal/database"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type VaultwardenRepository struct {
	sharesRepo *ConnectionShareRepository
}

func NewVaultwardenRepository() *VaultwardenRepository {
	return &VaultwardenRepository{
		sharesRepo: NewConnectionShareRepository(),
	}
}

func (r *VaultwardenRepository) SharesRepo() *ConnectionShareRepository {
	return r.sharesRepo
}

// GetConfig returns the raw config with decrypted MasterPassword for internal service use
func (r *VaultwardenRepository) GetConfig(ctx context.Context, userID int, userRole string, configID ...string) (*domain.VaultwardenConfig, error) {
	pool, err := database.GetPool()
	if err != nil {
		return nil, err
	}

	isAdmin := domain.IsAdminRole(userRole)
	targetID := ""
	if len(configID) > 0 && configID[0] != "" {
		targetID = configID[0]
	}

	var query string
	var rows pgx.Rows

	if targetID != "" {
		if isAdmin {
			query = `
				SELECT v.id, v.name, v.server_url, v.email, v.master_password_encrypted, v.is_active, v.last_synced_at, v.cached_ciphers, 
				       COALESCE(v.cached_folders, '[]'::jsonb),
				       v.user_id, COALESCE(u.username, 'Admin'), COALESCE(v.visibility, 'private'), v.created_at, v.updated_at,
				       (SELECT COUNT(*) FROM vaultwarden_shares WHERE config_id = v.id) AS shares_count,
				       'manage' AS user_permission
				FROM vaultwarden_configs v
				LEFT JOIN users u ON v.user_id = u.id
				WHERE v.id = $1
				LIMIT 1
			`
			rows, err = pool.Query(ctx, query, targetID)
		} else {
			query = `
				SELECT v.id, v.name, v.server_url, v.email, v.master_password_encrypted, v.is_active, v.last_synced_at, v.cached_ciphers, 
				       COALESCE(v.cached_folders, '[]'::jsonb),
				       v.user_id, COALESCE(u.username, 'Admin'), COALESCE(v.visibility, 'private'), v.created_at, v.updated_at,
				       (SELECT COUNT(*) FROM vaultwarden_shares WHERE config_id = v.id) AS shares_count,
				       COALESCE(vs.permission, CASE WHEN v.user_id = $2 THEN 'manage' WHEN v.visibility = 'public' THEN 'read' ELSE '' END) AS user_permission
				FROM vaultwarden_configs v
				LEFT JOIN users u ON v.user_id = u.id
				LEFT JOIN vaultwarden_shares vs ON v.id = vs.config_id AND vs.user_id = $2
				WHERE v.id = $1 AND (v.user_id = $2 OR vs.user_id = $2 OR v.visibility = 'public')
				LIMIT 1
			`
			rows, err = pool.Query(ctx, query, targetID, userID)
		}
	} else {
		// Get active configuration for current user
		if isAdmin {
			query = `
				SELECT v.id, v.name, v.server_url, v.email, v.master_password_encrypted, v.is_active, v.last_synced_at, v.cached_ciphers, 
				       COALESCE(v.cached_folders, '[]'::jsonb),
				       v.user_id, COALESCE(u.username, 'Admin'), COALESCE(v.visibility, 'private'), v.created_at, v.updated_at,
				       (SELECT COUNT(*) FROM vaultwarden_shares WHERE config_id = v.id) AS shares_count,
				       'manage' AS user_permission
				FROM vaultwarden_configs v
				LEFT JOIN users u ON v.user_id = u.id
				ORDER BY (v.user_id = $1) DESC, v.is_active DESC, v.updated_at DESC
				LIMIT 1
			`
			rows, err = pool.Query(ctx, query, userID)
		} else {
			query = `
				SELECT v.id, v.name, v.server_url, v.email, v.master_password_encrypted, v.is_active, v.last_synced_at, v.cached_ciphers, 
				       COALESCE(v.cached_folders, '[]'::jsonb),
				       v.user_id, COALESCE(u.username, 'Admin'), COALESCE(v.visibility, 'private'), v.created_at, v.updated_at,
				       (SELECT COUNT(*) FROM vaultwarden_shares WHERE config_id = v.id) AS shares_count,
				       COALESCE(vs.permission, CASE WHEN v.user_id = $1 THEN 'manage' WHEN v.visibility = 'public' THEN 'read' ELSE '' END) AS user_permission
				FROM vaultwarden_configs v
				LEFT JOIN users u ON v.user_id = u.id
				LEFT JOIN vaultwarden_shares vs ON v.id = vs.config_id AND vs.user_id = $1
				WHERE (v.user_id = $1 OR vs.user_id = $1 OR v.visibility = 'public')
				ORDER BY (v.user_id = $1) DESC, v.is_active DESC, v.updated_at DESC
				LIMIT 1
			`
			rows, err = pool.Query(ctx, query, userID)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to query vaultwarden config: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, nil
	}

	var cfg domain.VaultwardenConfig
	var encPassword string
	var cachedJSON []byte
	var cachedFoldersJSON []byte

	if err := rows.Scan(
		&cfg.ID, &cfg.Name, &cfg.ServerURL, &cfg.Email, &encPassword, &cfg.IsActive,
		&cfg.LastSyncedAt, &cachedJSON, &cachedFoldersJSON, &cfg.UserID, &cfg.OwnerUsername, &cfg.Visibility,
		&cfg.CreatedAt, &cfg.UpdatedAt, &cfg.SharesCount, &cfg.UserPermission,
	); err != nil {
		return nil, err
	}

	cfg.IsOwner = (cfg.UserID != nil && *cfg.UserID == userID) || isAdmin

	if encPassword != "" {
		decrypted, err := config.DecryptText(encPassword)
		if err == nil {
			cfg.MasterPassword = decrypted
		} else {
			cfg.MasterPassword = encPassword
		}
	}

	if len(cachedJSON) > 0 {
		_ = json.Unmarshal(cachedJSON, &cfg.CachedCiphers)
	}
	if len(cachedFoldersJSON) > 0 {
		_ = json.Unmarshal(cachedFoldersJSON, &cfg.CachedFolders)
	}

	return &cfg, nil
}

// GetConfigPublic returns the config with MasterPassword stripped for API responses
func (r *VaultwardenRepository) GetConfigPublic(ctx context.Context, userID int, userRole string, configID ...string) (*domain.VaultwardenConfig, error) {
	cfg, err := r.GetConfig(ctx, userID, userRole, configID...)
	if err != nil || cfg == nil {
		return cfg, err
	}
	cfg.MasterPassword = ""
	return cfg, nil
}

// ListConfigs returns all Vaultwarden instances accessible to the user
func (r *VaultwardenRepository) ListConfigs(ctx context.Context, userID int, userRole string) ([]domain.VaultwardenConfig, error) {
	pool, err := database.GetPool()
	if err != nil {
		return nil, err
	}

	isAdmin := domain.IsAdminRole(userRole)
	var query string
	var rows pgx.Rows

	if isAdmin {
		query = `
			SELECT v.id, v.name, v.server_url, v.email, v.is_active, v.last_synced_at, 
			       v.user_id, COALESCE(u.username, 'Admin'), COALESCE(v.visibility, 'private'), v.created_at, v.updated_at,
			       (SELECT COUNT(*) FROM vaultwarden_shares WHERE config_id = v.id) AS shares_count,
			       'manage' AS user_permission
			FROM vaultwarden_configs v
			LEFT JOIN users u ON v.user_id = u.id
			ORDER BY v.created_at DESC
		`
		rows, err = pool.Query(ctx, query)
	} else {
		query = `
			SELECT v.id, v.name, v.server_url, v.email, v.is_active, v.last_synced_at, 
			       v.user_id, COALESCE(u.username, 'Admin'), COALESCE(v.visibility, 'private'), v.created_at, v.updated_at,
			       (SELECT COUNT(*) FROM vaultwarden_shares WHERE config_id = v.id) AS shares_count,
			       COALESCE(vs.permission, CASE WHEN v.user_id = $1 THEN 'manage' WHEN v.visibility = 'public' THEN 'read' ELSE '' END) AS user_permission
			FROM vaultwarden_configs v
			LEFT JOIN users u ON v.user_id = u.id
			LEFT JOIN vaultwarden_shares vs ON v.id = vs.config_id AND vs.user_id = $1
			WHERE v.user_id = $1 OR vs.user_id = $1 OR v.visibility = 'public'
			ORDER BY (v.user_id = $1) DESC, v.created_at DESC
		`
		rows, err = pool.Query(ctx, query, userID)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []domain.VaultwardenConfig
	for rows.Next() {
		var c domain.VaultwardenConfig
		if err := rows.Scan(
			&c.ID, &c.Name, &c.ServerURL, &c.Email, &c.IsActive, &c.LastSyncedAt,
			&c.UserID, &c.OwnerUsername, &c.Visibility, &c.CreatedAt, &c.UpdatedAt,
			&c.SharesCount, &c.UserPermission,
		); err != nil {
			return nil, err
		}
		c.IsOwner = (c.UserID != nil && *c.UserID == userID) || isAdmin
		list = append(list, c)
	}
	if list == nil {
		list = []domain.VaultwardenConfig{}
	}
	return list, nil
}

// ListAllActiveConfigs is used by background auto-sync worker
func (r *VaultwardenRepository) ListAllActiveConfigs(ctx context.Context) ([]domain.VaultwardenConfig, error) {
	pool, err := database.GetPool()
	if err != nil {
		return nil, err
	}

	query := `
		SELECT id, name, server_url, email, master_password_encrypted, is_active, last_synced_at, user_id, created_at, updated_at
		FROM vaultwarden_configs
		WHERE is_active = true AND server_url != '' AND email != ''
	`
	rows, err := pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []domain.VaultwardenConfig
	for rows.Next() {
		var c domain.VaultwardenConfig
		var encPassword string
		if err := rows.Scan(
			&c.ID, &c.Name, &c.ServerURL, &c.Email, &encPassword, &c.IsActive,
			&c.LastSyncedAt, &c.UserID, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if encPassword != "" {
			if dec, err := config.DecryptText(encPassword); err == nil {
				c.MasterPassword = dec
			} else {
				c.MasterPassword = encPassword
			}
		}
		list = append(list, c)
	}
	return list, nil
}

// SaveConfig saves or updates a user-scoped Vaultwarden configuration
func (r *VaultwardenRepository) SaveConfig(ctx context.Context, cfg domain.VaultwardenConfig, userID int, userRole string) (*domain.VaultwardenConfig, error) {
	pool, err := database.GetPool()
	if err != nil {
		return nil, err
	}

	isAdmin := domain.IsAdminRole(userRole)
	if cfg.ID != "" {
		hasAccess, isOwner, perm, err := r.sharesRepo.CheckAccess(ctx, "vaultwarden_configs", "vaultwarden_shares", "config_id", cfg.ID, userID, userRole)
		if err == nil && (!hasAccess || (!isOwner && !isAdmin && perm != "manage")) {
			return nil, errors.New("access denied: you do not have permission to modify this vaultwarden connection")
		}
	} else {
		cfg.ID = fmt.Sprintf("vw-%s", uuid.New().String()[:8])
	}

	if cfg.Name == "" {
		cfg.Name = "Vaultwarden"
	}
	if cfg.Visibility != "public" {
		cfg.Visibility = "private"
	}

	var encPassword string
	if cfg.MasterPassword != "" {
		encrypted, err := config.EncryptText(cfg.MasterPassword)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt master password: %w", err)
		}
		encPassword = encrypted
	} else {
		// Retain existing password if not provided
		existing, err := r.GetConfig(ctx, userID, userRole, cfg.ID)
		if err == nil && existing != nil && existing.MasterPassword != "" {
			encPassword, _ = config.EncryptText(existing.MasterPassword)
		}
	}

	var uid *int
	if userID > 0 {
		uid = &userID
	}

	now := time.Now()
	_, err = pool.Exec(ctx, `
		INSERT INTO vaultwarden_configs (
			id, name, server_url, email, master_password_encrypted, is_active, user_id, visibility, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			server_url = EXCLUDED.server_url,
			email = EXCLUDED.email,
			master_password_encrypted = CASE WHEN EXCLUDED.master_password_encrypted <> '' THEN EXCLUDED.master_password_encrypted ELSE vaultwarden_configs.master_password_encrypted END,
			is_active = EXCLUDED.is_active,
			user_id = COALESCE(vaultwarden_configs.user_id, EXCLUDED.user_id),
			visibility = COALESCE(EXCLUDED.visibility, vaultwarden_configs.visibility),
			updated_at = EXCLUDED.updated_at
	`, cfg.ID, cfg.Name, cfg.ServerURL, cfg.Email, encPassword, cfg.IsActive, uid, cfg.Visibility, now)

	if err != nil {
		return nil, fmt.Errorf("failed to save vaultwarden config: %w", err)
	}

	return r.GetConfigPublic(ctx, userID, userRole, cfg.ID)
}

// UpdateCachedData persists decrypted ciphers and folders in JSONB cache for fast retrieval
func (r *VaultwardenRepository) UpdateCachedData(ctx context.Context, id string, ciphers []domain.VaultCredentialItem, folders []domain.VaultFolder, lastSynced time.Time) error {
	pool, err := database.GetPool()
	if err != nil {
		return err
	}

	rawCiphers, err := json.Marshal(ciphers)
	if err != nil {
		return fmt.Errorf("failed to marshal ciphers: %w", err)
	}

	if folders == nil {
		folders = []domain.VaultFolder{}
	}
	rawFolders, err := json.Marshal(folders)
	if err != nil {
		return fmt.Errorf("failed to marshal folders: %w", err)
	}

	_, err = pool.Exec(ctx, `
		UPDATE vaultwarden_configs
		SET cached_ciphers = $1, cached_folders = $2, last_synced_at = $3, updated_at = NOW()
		WHERE id = $4
	`, rawCiphers, rawFolders, lastSynced, id)

	return err
}

// UpdateCachedCiphers persists decrypted ciphers in JSONB cache for fast retrieval
func (r *VaultwardenRepository) UpdateCachedCiphers(ctx context.Context, id string, ciphers []domain.VaultCredentialItem, lastSynced time.Time) error {
	pool, err := database.GetPool()
	if err != nil {
		return err
	}

	rawJSON, err := json.Marshal(ciphers)
	if err != nil {
		return fmt.Errorf("failed to marshal ciphers: %w", err)
	}

	_, err = pool.Exec(ctx, `
		UPDATE vaultwarden_configs
		SET cached_ciphers = $1, last_synced_at = $2, updated_at = NOW()
		WHERE id = $3
	`, rawJSON, lastSynced, id)

	return err
}

// DeleteConfig removes the Vaultwarden integration configuration
func (r *VaultwardenRepository) DeleteConfig(ctx context.Context, id string, userID int, userRole string) error {
	pool, err := database.GetPool()
	if err != nil {
		return err
	}

	isAdmin := domain.IsAdminRole(userRole)
	if !isAdmin {
		var ownerID *int
		err = pool.QueryRow(ctx, `SELECT user_id FROM vaultwarden_configs WHERE id = $1`, id).Scan(&ownerID)
		if err != nil {
			return err
		}
		if ownerID == nil || *ownerID != userID {
			return errors.New("access denied: only connection owner or administrator can delete this vaultwarden configuration")
		}
	}

	_, err = pool.Exec(ctx, `DELETE FROM vaultwarden_configs WHERE id = $1`, id)
	return err
}
