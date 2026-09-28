package repository

import (
	"context"
	"encoding/json"
	"fmt"

	"go-hephaestus/internal/core/domain"
	"go-hephaestus/internal/database"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type TopologyRepository struct{}

func NewTopologyRepository() *TopologyRepository {
	return &TopologyRepository{}
}

// Sheets
func (r *TopologyRepository) ListSheets(ctx context.Context, userID int, userRole string) ([]domain.TopologySheet, error) {
	pool, err := database.GetPool()
	if err != nil {
		return nil, err
	}

	isAdmin := domain.IsAdminRole(userRole)
	var rows pgx.Rows

	if isAdmin || (userID == 0 && userRole == "ADMIN") {
		query := `
			SELECT 
				s.id, s.name, s.sort_order, s.user_id, 
				COALESCE(u.username, 'Admin') AS owner_username,
				COALESCE(s.visibility, 'private') AS visibility,
				s.created_at, s.updated_at,
				(SELECT COUNT(*) FROM topology_sheet_shares WHERE sheet_id = s.id) AS shares_count
			FROM topology_sheets s
			LEFT JOIN users u ON s.user_id = u.id
			ORDER BY s.sort_order ASC, s.id ASC
		`
		rows, err = pool.Query(ctx, query)
	} else {
		query := `
			SELECT 
				s.id, s.name, s.sort_order, s.user_id, 
				COALESCE(u.username, 'Admin') AS owner_username,
				COALESCE(s.visibility, 'private') AS visibility,
				s.created_at, s.updated_at,
				(SELECT COUNT(*) FROM topology_sheet_shares WHERE sheet_id = s.id) AS shares_count,
				COALESCE(tss.permission, '') AS share_perm
			FROM topology_sheets s
			LEFT JOIN users u ON s.user_id = u.id
			LEFT JOIN topology_sheet_shares tss ON s.id = tss.sheet_id AND tss.user_id = $1
			WHERE s.visibility = 'public'
			   OR s.user_id = $1
			   OR tss.user_id = $1
			ORDER BY s.sort_order ASC, s.id ASC
		`
		rows, err = pool.Query(ctx, query, userID)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sheets []domain.TopologySheet
	for rows.Next() {
		var s domain.TopologySheet
		var sharePerm string
		if isAdmin || (userID == 0 && userRole == "ADMIN") {
			if err := rows.Scan(&s.ID, &s.Name, &s.SortOrder, &s.UserID, &s.OwnerUsername, &s.Visibility, &s.CreatedAt, &s.UpdatedAt, &s.SharesCount); err != nil {
				return nil, err
			}
			s.IsOwner = true
			s.UserPermission = "manage"
		} else {
			if err := rows.Scan(&s.ID, &s.Name, &s.SortOrder, &s.UserID, &s.OwnerUsername, &s.Visibility, &s.CreatedAt, &s.UpdatedAt, &s.SharesCount, &sharePerm); err != nil {
				return nil, err
			}
			s.IsOwner = (s.UserID != nil && *s.UserID == userID)
			if s.IsOwner {
				s.UserPermission = "manage"
			} else if sharePerm != "" {
				s.UserPermission = sharePerm
			} else if s.Visibility == "public" {
				s.UserPermission = "public"
			} else {
				s.UserPermission = "read"
			}
		}
		sheets = append(sheets, s)
	}
	if sheets == nil {
		sheets = []domain.TopologySheet{}
	}
	return sheets, nil
}

func (r *TopologyRepository) CreateSheet(ctx context.Context, name string, sortOrder int, userID *int, visibility string) (*domain.TopologySheet, error) {
	pool, err := database.GetPool()
	if err != nil {
		return nil, err
	}
	if visibility != "public" {
		visibility = "private"
	}
	var s domain.TopologySheet
	s.Name = name
	s.SortOrder = sortOrder
	s.UserID = userID
	s.Visibility = visibility
	s.IsOwner = true
	s.UserPermission = "manage"
	s.SharesCount = 0

	err = pool.QueryRow(ctx, `
		INSERT INTO topology_sheets (name, sort_order, user_id, visibility) 
		VALUES ($1, $2, $3, $4) 
		RETURNING id, created_at, updated_at
	`, name, sortOrder, userID, visibility).Scan(&s.ID, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *TopologyRepository) UpdateSheet(ctx context.Context, id int, name string, sortOrder int) error {
	pool, err := database.GetPool()
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `UPDATE topology_sheets SET name = $1, sort_order = $2, updated_at = NOW() WHERE id = $3`, name, sortOrder, id)
	return err
}

func (r *TopologyRepository) UpdateSheetVisibility(ctx context.Context, id int, visibility string) error {
	pool, err := database.GetPool()
	if err != nil {
		return err
	}
	if visibility != "public" {
		visibility = "private"
	}
	_, err = pool.Exec(ctx, `UPDATE topology_sheets SET visibility = $1, updated_at = NOW() WHERE id = $2`, visibility, id)
	return err
}

func (r *TopologyRepository) DeleteSheet(ctx context.Context, id int) error {
	pool, err := database.GetPool()
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `DELETE FROM topology_sheets WHERE id = $1`, id)
	return err
}

func (r *TopologyRepository) CheckSheetAccess(ctx context.Context, sheetID int, userID int, userRole string) (hasAccess bool, isOwner bool, perm string, err error) {
	if domain.IsAdminRole(userRole) {
		return true, true, "manage", nil
	}

	pool, err := database.GetPool()
	if err != nil {
		return false, false, "", err
	}

	query := `
		SELECT 
			s.user_id,
			COALESCE(s.visibility, 'private'),
			(s.user_id = $2) AS is_owner,
			COALESCE(tss.permission, '') AS share_perm
		FROM topology_sheets s
		LEFT JOIN topology_sheet_shares tss ON s.id = tss.sheet_id AND tss.user_id = $2
		WHERE s.id = $1
	`
	var ownerID *int
	var visibility string
	var ownerBool bool
	var sharePerm string
	err = pool.QueryRow(ctx, query, sheetID, userID).Scan(&ownerID, &visibility, &ownerBool, &sharePerm)
	if err != nil {
		return false, false, "", err
	}

	if ownerBool {
		return true, true, "manage", nil
	}
	if sharePerm != "" {
		return true, false, sharePerm, nil
	}
	if visibility == "public" {
		return true, false, "read", nil
	}

	return false, false, "", nil
}

// Sheet Shares
func (r *TopologyRepository) ListSheetShares(ctx context.Context, sheetID int) ([]domain.TopologySheetShare, error) {
	pool, err := database.GetPool()
	if err != nil {
		return nil, err
	}

	query := `
		SELECT s.id, s.sheet_id, s.user_id, u.username, s.permission,
		       s.shared_by, COALESCE(sb.username, 'Admin') AS shared_by_username, s.created_at
		FROM topology_sheet_shares s
		JOIN users u ON s.user_id = u.id
		LEFT JOIN users sb ON s.shared_by = sb.id
		WHERE s.sheet_id = $1
		ORDER BY s.created_at DESC
	`
	rows, err := pool.Query(ctx, query, sheetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var shares []domain.TopologySheetShare
	for rows.Next() {
		var s domain.TopologySheetShare
		if err := rows.Scan(&s.ID, &s.SheetID, &s.UserID, &s.Username, &s.Permission, &s.SharedBy, &s.SharedByUsername, &s.CreatedAt); err != nil {
			return nil, err
		}
		shares = append(shares, s)
	}
	if shares == nil {
		shares = []domain.TopologySheetShare{}
	}
	return shares, nil
}

func (r *TopologyRepository) AddSheetShare(ctx context.Context, sheetID int, targetUserID int, permission string, sharedBy int) error {
	pool, err := database.GetPool()
	if err != nil {
		return err
	}

	if permission != "manage" {
		permission = "read"
	}

	shareID := fmt.Sprintf("tss-%s", uuid.New().String()[:8])
	query := `
		INSERT INTO topology_sheet_shares (id, sheet_id, user_id, permission, shared_by, created_at)
		VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
		ON CONFLICT (sheet_id, user_id) DO UPDATE SET
			permission = EXCLUDED.permission,
			shared_by = EXCLUDED.shared_by,
			created_at = CURRENT_TIMESTAMP
	`
	_, err = pool.Exec(ctx, query, shareID, sheetID, targetUserID, permission, sharedBy)
	return err
}

func (r *TopologyRepository) DeleteSheetShare(ctx context.Context, sheetID int, targetUserID int) error {
	pool, err := database.GetPool()
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `DELETE FROM topology_sheet_shares WHERE sheet_id = $1 AND user_id = $2`, sheetID, targetUserID)
	return err
}

func (r *TopologyRepository) ListAvailableUsers(ctx context.Context) ([]map[string]interface{}, error) {
	pool, err := database.GetPool()
	if err != nil {
		return nil, err
	}

	query := `SELECT id, username, role FROM users ORDER BY username ASC`
	rows, err := pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var id int
		var username, role string
		if err := rows.Scan(&id, &username, &role); err != nil {
			continue
		}
		users = append(users, map[string]interface{}{
			"id":       id,
			"username": username,
			"role":     role,
		})
	}
	if users == nil {
		users = []map[string]interface{}{}
	}
	return users, nil
}

// Devices
func (r *TopologyRepository) ListDevices(ctx context.Context, sheetID *int) ([]domain.TopologyDevice, error) {
	pool, err := database.GetPool()
	if err != nil {
		return nil, err
	}

	query := `SELECT id, name, ip_address, device_type, status, sources, labels, interfaces, sheet_id, x, y, created_at 
              FROM topology_devices 
              WHERE ($1::int IS NULL 
                 OR sheet_id = $1 
                 OR id IN (
                     SELECT source_id FROM topology_edges WHERE sheet_id = $1 
                     UNION 
                     SELECT target_id FROM topology_edges WHERE sheet_id = $1
                 )) 
              ORDER BY name ASC`
	rows, err := pool.Query(ctx, query, sheetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []domain.TopologyDevice
	for rows.Next() {
		var d domain.TopologyDevice
		var labelsRaw, ifacesRaw []byte
		if err := rows.Scan(&d.ID, &d.Name, &d.IPAddress, &d.DeviceType, &d.Status, &d.Sources, &labelsRaw, &ifacesRaw, &d.SheetID, &d.X, &d.Y, &d.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(labelsRaw, &d.Labels)
		_ = json.Unmarshal(ifacesRaw, &d.Interfaces)
		devices = append(devices, d)
	}
	return devices, nil
}

func (r *TopologyRepository) SaveDevice(ctx context.Context, d domain.TopologyDevice) error {
	pool, err := database.GetPool()
	if err != nil {
		return err
	}

	labelsJSON, _ := json.Marshal(d.Labels)
	if len(labelsJSON) == 0 {
		labelsJSON = []byte("{}")
	}
	ifacesJSON, _ := json.Marshal(d.Interfaces)
	if len(ifacesJSON) == 0 {
		ifacesJSON = []byte("[]")
	}

	query := `INSERT INTO topology_devices (id, name, ip_address, device_type, status, sources, labels, interfaces, sheet_id, x, y)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
              ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name, ip_address = EXCLUDED.ip_address, device_type = EXCLUDED.device_type,
                status = EXCLUDED.status, sources = EXCLUDED.sources, labels = EXCLUDED.labels,
                interfaces = EXCLUDED.interfaces, sheet_id = EXCLUDED.sheet_id, x = EXCLUDED.x, y = EXCLUDED.y`
	_, err = pool.Exec(ctx, query, d.ID, d.Name, d.IPAddress, d.DeviceType, d.Status, d.Sources, labelsJSON, ifacesJSON, d.SheetID, d.X, d.Y)
	return err
}

func (r *TopologyRepository) UpdatePosition(ctx context.Context, id string, x, y float64) error {
	pool, err := database.GetPool()
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `UPDATE topology_devices SET x = $1, y = $2 WHERE id = $3`, x, y, id)
	return err
}

func (r *TopologyRepository) DeleteDevice(ctx context.Context, id string) error {
	pool, err := database.GetPool()
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `DELETE FROM topology_devices WHERE id = $1`, id)
	return err
}

func (r *TopologyRepository) RemoveDeviceFromCanvas(ctx context.Context, id string, sheetID *int) error {
	pool, err := database.GetPool()
	if err != nil {
		return err
	}

	// 1. Delete edges attached to this device on this sheet
	if sheetID != nil {
		_, _ = pool.Exec(ctx, `DELETE FROM topology_edges WHERE (source_id = $1 OR target_id = $1) AND (sheet_id = $2 OR sheet_id IS NULL)`, id, *sheetID)
	} else {
		_, _ = pool.Exec(ctx, `DELETE FROM topology_edges WHERE source_id = $1 OR target_id = $1`, id)
	}

	// 2. Set sheet_id to NULL, x to NULL, y to NULL (unplaced from canvas)
	if sheetID != nil {
		_, err = pool.Exec(ctx, `UPDATE topology_devices SET sheet_id = NULL, x = NULL, y = NULL WHERE id = $1 AND (sheet_id = $2 OR sheet_id IS NULL)`, id, *sheetID)
	} else {
		_, err = pool.Exec(ctx, `UPDATE topology_devices SET sheet_id = NULL, x = NULL, y = NULL WHERE id = $1`, id)
	}
	return err
}

// Edges
func (r *TopologyRepository) ListEdges(ctx context.Context, sheetID *int) ([]domain.TopologyEdge, error) {
	pool, err := database.GetPool()
	if err != nil {
		return nil, err
	}

	query := `SELECT id, source_id, target_id, label, source_label, target_label, edge_type, sheet_id, created_at 
              FROM topology_edges WHERE ($1::int IS NULL OR sheet_id = $1)`
	rows, err := pool.Query(ctx, query, sheetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var edges []domain.TopologyEdge
	for rows.Next() {
		var e domain.TopologyEdge
		if err := rows.Scan(&e.ID, &e.SourceID, &e.TargetID, &e.Label, &e.SourceLabel, &e.TargetLabel, &e.EdgeType, &e.SheetID, &e.CreatedAt); err != nil {
			return nil, err
		}
		edges = append(edges, e)
	}
	return edges, nil
}

func (r *TopologyRepository) SaveEdge(ctx context.Context, e domain.TopologyEdge) error {
	pool, err := database.GetPool()
	if err != nil {
		return err
	}

	if e.ID > 0 {
		query := `UPDATE topology_edges 
                  SET source_id = $1, target_id = $2, label = $3, source_label = $4, target_label = $5, edge_type = $6 
                  WHERE id = $7`
		_, err = pool.Exec(ctx, query, e.SourceID, e.TargetID, e.Label, e.SourceLabel, e.TargetLabel, e.EdgeType, e.ID)
		return err
	}

	query := `INSERT INTO topology_edges (source_id, target_id, label, source_label, target_label, edge_type, sheet_id)
              VALUES ($1, $2, $3, $4, $5, $6, $7)
              ON CONFLICT (source_id, target_id, sheet_id) DO UPDATE SET
                label = EXCLUDED.label, source_label = EXCLUDED.source_label,
                target_label = EXCLUDED.target_label, edge_type = EXCLUDED.edge_type`
	_, err = pool.Exec(ctx, query, e.SourceID, e.TargetID, e.Label, e.SourceLabel, e.TargetLabel, e.EdgeType, e.SheetID)
	return err
}

func (r *TopologyRepository) DeleteEdge(ctx context.Context, id int) error {
	pool, err := database.GetPool()
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `DELETE FROM topology_edges WHERE id = $1`, id)
	return err
}

// Device Ping Results
func (r *TopologyRepository) SavePingResult(ctx context.Context, res domain.DevicePingResult) error {
	return r.SavePingResultsBatch(ctx, []domain.DevicePingResult{res})
}

// SavePingResultsBatch executes batch insertion and status updates inside a single database transaction
func (r *TopologyRepository) SavePingResultsBatch(ctx context.Context, results []domain.DevicePingResult) error {
	if len(results) == 0 {
		return nil
	}

	pool, err := database.GetPool()
	if err != nil {
		return err
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	insertQuery := `INSERT INTO device_ping_results (device_id, ip, reachable, latency_ms, checked_at)
              VALUES ($1, $2, $3, $4, $5)
              ON CONFLICT (device_id) DO UPDATE SET
                ip = EXCLUDED.ip, reachable = EXCLUDED.reachable,
                latency_ms = EXCLUDED.latency_ms, checked_at = EXCLUDED.checked_at`

	updateStatusQuery := `UPDATE topology_devices SET status = $1 WHERE id = $2`

	for _, res := range results {
		if _, err := tx.Exec(ctx, insertQuery, res.DeviceID, res.IP, res.Reachable, res.LatencyMS, res.CheckedAt); err != nil {
			return err
		}

		status := "offline"
		if res.Reachable {
			status = "online"
		}
		if _, err := tx.Exec(ctx, updateStatusQuery, status, res.DeviceID); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (r *TopologyRepository) ListPingResults(ctx context.Context) ([]domain.DevicePingResult, error) {
	pool, err := database.GetPool()
	if err != nil {
		return nil, err
	}

	query := `SELECT device_id, ip, reachable, latency_ms, checked_at FROM device_ping_results ORDER BY checked_at DESC`
	rows, err := pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []domain.DevicePingResult
	for rows.Next() {
		var res domain.DevicePingResult
		if err := rows.Scan(&res.DeviceID, &res.IP, &res.Reachable, &res.LatencyMS, &res.CheckedAt); err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	return results, nil
}
