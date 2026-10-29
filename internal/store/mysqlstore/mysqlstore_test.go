package mysqlstore_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/migrate"
	"github.com/excalibase/auth/internal/store"
	"github.com/excalibase/auth/internal/store/mysqlstore"
	"github.com/excalibase/auth/internal/store/storetest"
	"github.com/excalibase/auth/internal/testmysql"
)

func authLogin(record map[string]string) mysqlstore.Login {
	return mysqlstore.Login{
		Host: record["host"], Port: record["port"], Database: record["database"],
		Username: record["username"], Password: record["password"], ServerCA: record["sslrootcert"],
	}
}

// openMigrated migrates and opens the auth database as auth_admin, holding
// only the grant provisioning gives it.
func openMigrated(t *testing.T) (*testmysql.Server, *mysqlstore.Store) {
	t.Helper()
	server := testmysql.Start(t)
	config, err := mysqlstore.Config(authLogin(server.ProvisionAuth(t, "auth-admin-pw")))
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.RunMySQL(context.Background(), config); err != nil {
		t.Fatalf("migrate as auth_admin: %v", err)
	}
	db, err := mysqlstore.Open(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return server, db
}

func TestIntegration_MySQLStoreKeepsTheStoreContract(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	server, db := openMigrated(t)
	root := server.Root(t)
	storetest.Run(t, storetest.Fixture{
		Store: db,
		Grandfather: func(t *testing.T, email string) {
			if _, err := root.Exec("UPDATE `auth`.`users` SET email_verified = TRUE WHERE email = ?", email); err != nil {
				t.Fatal(err)
			}
		},
		Disable: func(t *testing.T, email string) {
			if _, err := root.Exec("UPDATE `auth`.`users` SET enabled = FALSE WHERE email = ?", email); err != nil {
				t.Fatal(err)
			}
		},
		SetEmail: func(t *testing.T, id int64, email string) {
			if _, err := root.Exec("UPDATE `auth`.`users` SET email = ? WHERE id = ?", email, id); err != nil {
				t.Fatal(err)
			}
		},
		Reference: func(t *testing.T, id int64) {
			if _, err := root.Exec("CREATE TABLE IF NOT EXISTS `auth`.`app_owners` (user_id BIGINT, " +
				"FOREIGN KEY (user_id) REFERENCES `auth`.`users` (id))"); err != nil {
				t.Fatal(err)
			}
			if _, err := root.Exec("INSERT INTO `auth`.`app_owners` (user_id) VALUES (?)", id); err != nil {
				t.Fatal(err)
			}
		},
		Backdate: func(t *testing.T, id int64, age time.Duration) {
			seconds := int64(age.Seconds())
			if _, err := root.Exec("UPDATE `auth`.`users` SET created_at = UTC_TIMESTAMP(6) - INTERVAL ? SECOND, "+
				"last_login_at = UTC_TIMESTAMP(6) - INTERVAL ? SECOND WHERE id = ?", seconds, seconds, id); err != nil {
				t.Fatal(err)
			}
			if _, err := root.Exec("UPDATE `auth`.`refresh_tokens` SET created_at = UTC_TIMESTAMP(6) - INTERVAL ? SECOND "+
				"WHERE user_id = ?", seconds, id); err != nil {
				t.Fatal(err)
			}
		},
		Count: func(t *testing.T, table string) int {
			var n int
			if err := root.QueryRow("SELECT COUNT(*) FROM `auth`.`" + table + "`").Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		},
	})
}

func TestIntegration_MySQLMigrationsAreRepeatableAndCompareTextByteForByte(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	server, db := openMigrated(t)
	config, _ := mysqlstore.Config(authLogin(map[string]string{
		"host": server.Host, "port": server.Port, "database": "auth",
		"username": "auth_admin", "password": "auth-admin-pw", "sslrootcert": server.CAPEM,
	}))
	if err := migrate.RunMySQL(context.Background(), config); err != nil {
		t.Fatalf("second run: %v", err)
	}
	rows, err := server.Root(t).Query(`SELECT TABLE_NAME, TABLE_COLLATION FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'auth'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	tables := map[string]string{}
	for rows.Next() {
		var name, collation string
		if err := rows.Scan(&name, &collation); err != nil {
			t.Fatal(err)
		}
		tables[name] = collation
	}
	for _, table := range []string{"users", "refresh_tokens", "api_keys", "email_verification_tokens", "password_reset_tokens", "role_changes",
		"identities", "flow_states", "auth_codes"} {
		if tables[table] != "utf8mb4_0900_bin" {
			t.Errorf("%s collation = %q, want utf8mb4_0900_bin", table, tables[table])
		}
	}
	for _, column := range []string{"password", "email"} {
		var nullable string
		if err := server.Root(t).QueryRow(`SELECT IS_NULLABLE FROM information_schema.COLUMNS
			WHERE TABLE_SCHEMA = 'auth' AND TABLE_NAME = 'users' AND COLUMN_NAME = ?`, column).Scan(&nullable); err != nil || nullable != "YES" {
			t.Errorf("auth.users.%s nullable = %q err=%v", column, nullable, err)
		}
	}
	_ = db
}

func TestMySQLConfigVerifiesTheServerAgainstTheRecordsCA(t *testing.T) {
	config, err := mysqlstore.Config(mysqlstore.Login{
		Host: "moco-p1-mysql-primary.ns.svc", Port: "3306", Database: "auth",
		Username: "auth_admin", Password: "pw", ServerCA: testCA(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.TLS == nil || config.TLS.ServerName != "moco-p1-mysql-primary.ns.svc" || config.TLS.RootCAs == nil || config.TLS.InsecureSkipVerify {
		t.Fatalf("tls = %+v", config.TLS)
	}
	if config.MultiStatements || config.InterpolateParams || config.AllowAllFiles || config.AllowCleartextPasswords {
		t.Fatalf("unsafe options on: %+v", config)
	}
	if config.DBName != "auth" || config.User != "auth_admin" || config.Addr != "moco-p1-mysql-primary.ns.svc:3306" || !config.ParseTime {
		t.Fatalf("config = %+v", config)
	}
}

func TestMySQLConfigRefusesALoginWithoutAUsableCA(t *testing.T) {
	for name, ca := range map[string]string{"missing": "", "not PEM": "not a certificate"} {
		_, err := mysqlstore.Config(mysqlstore.Login{Host: "h", Port: "3306", Database: "auth", Username: "u", Password: "secret-pw", ServerCA: ca})
		if err == nil {
			t.Fatalf("%s CA accepted", name)
		}
		if contains(err.Error(), "secret-pw") {
			t.Fatalf("error carries the password: %v", err)
		}
	}
}

// Whatever the instance's own sql_mode, auth's sessions are strict, so bad
// values fail as they do on Postgres instead of being adjusted.
func TestMySQLConfigPinsAStrictSQLMode(t *testing.T) {
	config, err := mysqlstore.Config(mysqlstore.Login{Host: "h", Port: "3306", Database: "auth", Username: "u", Password: "p", ServerCA: testCA(t)})
	if err != nil {
		t.Fatal(err)
	}
	if mode := config.Params["sql_mode"]; !contains(mode, "STRICT_ALL_TABLES") || !contains(mode, "NO_ZERO_DATE") {
		t.Fatalf("sql_mode = %q", mode)
	}
}

// EXC-650: a login right after an in-place restore answered 504. A pooled
// connection to a server that stopped answering must fail the call in
// seconds, not hold the request until the edge gives up.
func TestIntegration_MySQLStoreFailsFastWhenTheServerStopsAnswering(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	server, db := openMigrated(t)
	ctx := context.Background()
	if _, err := db.AccountByEmail(ctx, "nobody@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("warm the pool: %v", err)
	}
	server.Freeze(t)
	started := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := db.AccountByEmail(ctx, "nobody@example.com")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a frozen server answered: %v", err)
		}
		if elapsed := time.Since(started); elapsed > 20*time.Second {
			t.Fatalf("the call failed only after %s", elapsed)
		}
	case <-time.After(40 * time.Second):
		t.Fatal("the call hung on a server that stopped answering")
	}
}
