package reconcile

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v6/plugins/cliproxy-access-manager/internal/store"
)

func TestCompareSemver(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		latest  string
		current string
		want    int
		wantErr bool
	}{
		{name: "patch greater", latest: "v1.2.10", current: "v1.2.9", want: 1},
		{name: "v prefix equal", latest: "1.2.3", current: "v1.2.3", want: 0},
		{name: "rc less than stable", latest: "1.2.3-rc.1", current: "1.2.3", want: -1},
		{name: "invalid latest", latest: "not-a-version", current: "1.2.3", wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := compareSemver(tt.latest, tt.current)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("compareSemver error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("compareSemver got=%d want=%d", got, tt.want)
			}
		})
	}
}

func TestCheckMainProjectUpdateNowAutoApplyTrigger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		latest    string
		current   string
		autoApply bool
		wantCalls int
	}{
		{name: "update available and enabled", latest: "1.2.4", current: "1.2.3", autoApply: true, wantCalls: 1},
		{name: "update available but disabled", latest: "1.2.4", current: "1.2.3", autoApply: false, wantCalls: 0},
		{name: "no update available", latest: "1.2.3", current: "1.2.3", autoApply: true, wantCalls: 0},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			m := &Manager{
				latestVersionEndpoint:  "/latest",
				updateAutoApplyEnabled: tt.autoApply,
				applyUpdateFn: func(context.Context) error {
					calls++
					return nil
				},
				getLatestVersionFn: func(context.Context, string) (string, string, error) {
					return tt.latest, tt.current, nil
				},
			}
			if err := m.checkMainProjectUpdateNowInternal(context.Background(), true); err != nil {
				t.Fatalf("checkMainProjectUpdateNowInternal error: %v", err)
			}
			if calls != tt.wantCalls {
				t.Fatalf("apply calls=%d want=%d", calls, tt.wantCalls)
			}
		})
	}
}

func TestCheckMainProjectUpdateNowInvalidVersion(t *testing.T) {
	t.Parallel()
	m := &Manager{
		latestVersionEndpoint: "/latest",
		getLatestVersionFn: func(context.Context, string) (string, string, error) {
			return "broken", "1.2.3", nil
		},
	}
	if err := m.checkMainProjectUpdateNowInternal(context.Background(), true); err != nil {
		t.Fatalf("checkMainProjectUpdateNowInternal error: %v", err)
	}
}

func TestRunCustomUpdateCommandGate(t *testing.T) {
	t.Parallel()
	m := &Manager{updateAllowCustomCommand: false}
	_, err := m.runCustomUpdateCommand(context.Background(), "printf hello")
	if err == nil {
		t.Fatalf("expected error when custom command is disabled")
	}
	if !strings.Contains(err.Error(), "APIM_UPDATE_ALLOW_CUSTOM_COMMAND=false") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNormalizeVersion(t *testing.T) {
	t.Parallel()
	got, err := normalizeVersion("1.2.3")
	if err != nil {
		t.Fatalf("normalizeVersion error: %v", err)
	}
	if got != "v1.2.3" {
		t.Fatalf("normalizeVersion got=%s want=v1.2.3", got)
	}
}

func TestCheckMainProjectUpdateNowWrapperNilFn(t *testing.T) {
	t.Parallel()
	m := &Manager{}
	if err := m.CheckMainProjectUpdateNow(context.Background()); err == nil {
		t.Fatalf("expected error")
	}
}

func TestApplyMainProjectUpdateNowWrapperNilFn(t *testing.T) {
	t.Parallel()
	m := &Manager{}
	if err := m.ApplyMainProjectUpdateNow(context.Background()); err == nil {
		t.Fatalf("expected error")
	}
}

func TestCompareSemverErrorDetails(t *testing.T) {
	t.Parallel()
	_, err := compareSemver("1.2.3", "broken")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "invalid current version") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckMainProjectUpdateNowAutoApplyErrorBubbles(t *testing.T) {
	t.Parallel()
	m := &Manager{
		latestVersionEndpoint:  "/latest",
		updateAutoApplyEnabled: true,
		applyUpdateFn: func(context.Context) error {
			return errors.New("apply boom")
		},
		getLatestVersionFn: func(context.Context, string) (string, string, error) {
			return "1.2.4", "1.2.3", nil
		},
	}
	if err := m.checkMainProjectUpdateNowInternal(context.Background(), true); err == nil {
		t.Fatalf("expected error")
	}
}

func TestEvaluateUsageControlsNowSyncsWhenChanged(t *testing.T) {
	t.Parallel()
	calledEval := 0
	calledSync := 0
	m := &Manager{
		evaluateUsageControlsFn: func(context.Context, string) ([]store.UsageControlEvaluationResult, bool, error) {
			calledEval++
			return []store.UsageControlEvaluationResult{{ControlID: 1, Triggered: true}}, true, nil
		},
		syncKeysFn: func(context.Context) error {
			calledSync++
			return nil
		},
	}
	results, changed, err := m.EvaluateUsageControlsNow(context.Background(), "tester")
	if err != nil {
		t.Fatalf("EvaluateUsageControlsNow error: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}
	if calledEval != 1 || calledSync != 1 {
		t.Fatalf("calls eval=%d sync=%d want 1/1", calledEval, calledSync)
	}
	if len(results) != 1 {
		t.Fatalf("len(results)=%d want=1", len(results))
	}
}

func TestEvaluateUsageControlsNowNoChangeNoSync(t *testing.T) {
	t.Parallel()
	calledSync := 0
	m := &Manager{
		evaluateUsageControlsFn: func(context.Context, string) ([]store.UsageControlEvaluationResult, bool, error) {
			return nil, false, nil
		},
		syncKeysFn: func(context.Context) error {
			calledSync++
			return nil
		},
	}
	_, changed, err := m.EvaluateUsageControlsNow(context.Background(), "tester")
	if err != nil {
		t.Fatalf("EvaluateUsageControlsNow error: %v", err)
	}
	if changed {
		t.Fatalf("expected changed=false")
	}
	if calledSync != 0 {
		t.Fatalf("sync called=%d want=0", calledSync)
	}
}
