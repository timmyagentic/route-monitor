package main

import (
	"database/sql"
	"errors"
	"strings"
	"unicode/utf8"
)

var errHandlingReason = errors.New("请填写处理原因（1–300字）")

func validHandlingReason(reason string) bool {
	n := utf8.RuneCountInString(strings.TrimSpace(reason))
	return n > 0 && n <= 300
}

// Additive migration. Seed known signatures once, without acknowledging any active domain.
func migrateHandling(db *sql.DB) error {
	rows, e := db.Query(`PRAGMA table_info(domain_handling)`)
	if e != nil {
		return e
	}
	hasReason := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var def any
		if e = rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); e != nil {
			rows.Close()
			return e
		}
		hasReason = hasReason || name == "handled_reason"
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	tx, e := db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if !hasReason {
		if _, e = tx.Exec(`ALTER TABLE domain_handling ADD COLUMN handled_reason TEXT NOT NULL DEFAULT ''`); e != nil {
			return e
		}
	}
	if _, e = tx.Exec(`CREATE TABLE IF NOT EXISTS handled_errors(domain TEXT NOT NULL,route TEXT NOT NULL,error TEXT NOT NULL,PRIMARY KEY(domain,route,error));
 CREATE TABLE IF NOT EXISTS app_migrations(name TEXT PRIMARY KEY);`); e != nil {
		return e
	}
	var migrated bool
	if e = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM app_migrations WHERE name='handling-reasons-v1')`).Scan(&migrated); e != nil {
		return e
	}
	if !migrated {
		if _, e = tx.Exec(`INSERT OR IGNORE INTO handled_errors SELECT DISTINCT e.domain,COALESCE(e.route,''),COALESCE(e.error,'') FROM events e JOIN domain_handling h ON h.domain=e.domain WHERE e.kind='error' AND h.handled_revision=h.error_revision;
  INSERT INTO app_migrations VALUES('handling-reasons-v1');`); e != nil {
			return e
		}
	}
	return tx.Commit()
}
