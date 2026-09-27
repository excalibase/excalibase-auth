package migrate

import (
	"strings"
	"testing"
)

func TestMigrationURLKeepsTheConnectionsSSLMode(t *testing.T) {
	url, err := connStrToURL("host=h port=5432 user=u password=p dbname=d sslmode=require")
	if err != nil {
		t.Fatalf("connStrToURL: %v", err)
	}
	if !strings.Contains(url, "sslmode=require") {
		t.Fatalf("migration URL dropped TLS: %q", url)
	}
}

func TestMigrationURLRefusesAConnectionThatStatesNoSSLMode(t *testing.T) {
	if _, err := connStrToURL("host=h port=5432 user=u password=p dbname=d"); err == nil {
		t.Fatal("a connection string with no sslmode must be refused, not assumed plaintext")
	}
}

func TestSchemaBootstrapURLKeepsTheConnectionsSSLMode(t *testing.T) {
	url, err := schemaBootstrapURL("host=h port=5432 user=u password=p dbname=d sslmode=require")
	if err != nil {
		t.Fatalf("schemaBootstrapURL: %v", err)
	}
	if !strings.Contains(url, "sslmode=require") {
		t.Fatalf("schema bootstrap dropped TLS: %q", url)
	}
}
