package telegram

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v6/plugins/cliproxy-access-manager/internal/store"
)

func TestUserRoleCanUseHelp(t *testing.T) {
	t.Parallel()
	b := &Bot{}
	resp := b.executeCommand(context.Background(), "/help", 1, 2, &store.Principal{Role: store.IdentityRoleUser, Email: "user@example.com"})
	if resp == "" {
		t.Fatalf("expected help response")
	}
}

func TestUserRoleCannotUseAdminCommand(t *testing.T) {
	t.Parallel()
	b := &Bot{}
	resp := b.executeCommand(context.Background(), "/status", 1, 2, &store.Principal{Role: store.IdentityRoleUser, Email: "user@example.com"})
	if resp != "Access denied." {
		t.Fatalf("unexpected response: %s", resp)
	}
}

func TestNilPrincipalDenied(t *testing.T) {
	t.Parallel()
	b := &Bot{}
	resp := b.executeCommand(context.Background(), "/help", 1, 2, nil)
	if resp != "Access denied." {
		t.Fatalf("unexpected response: %s", resp)
	}
}
