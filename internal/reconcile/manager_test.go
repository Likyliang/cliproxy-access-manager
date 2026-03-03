package reconcile

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

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

func TestStartMainProjectUpdateApplyStateTransition(t *testing.T) {
	t.Parallel()

	m := &Manager{}

	applyDone := make(chan struct{})
	m.applyUpdateFn = func(context.Context) error {
		close(applyDone)
		return nil
	}
	m.updateCheckFn = func(context.Context) error { return nil }

	job, accepted, err := m.StartMainProjectUpdateApply(context.Background(), "manual")
	if err != nil {
		t.Fatalf("StartMainProjectUpdateApply error: %v", err)
	}
	if !accepted {
		t.Fatalf("accepted=%v want=true", accepted)
	}
	if strings.TrimSpace(job.ID) == "" {
		t.Fatalf("job id is empty")
	}
	if job.State != UpdateApplyStateRunning {
		t.Fatalf("job state=%s want=%s", job.State, UpdateApplyStateRunning)
	}
	if currentRunning := m.CurrentUpdateApplyJob(); currentRunning == nil || currentRunning.State != UpdateApplyStateRunning {
		t.Fatalf("expected running state before completion, got=%+v", currentRunning)
	}

	select {
	case <-applyDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting apply to complete")
	}

	m.Wait()

	current := m.CurrentUpdateApplyJob()
	if current == nil {
		t.Fatalf("current update job should exist")
	}
	if current.State != UpdateApplyStateSucceeded {
		t.Fatalf("final state=%s want=%s", current.State, UpdateApplyStateSucceeded)
	}
	if current.FinishedAt == nil {
		t.Fatalf("finished_at should be set")
	}
	if current.Error != "" {
		t.Fatalf("unexpected error: %s", current.Error)
	}
}

func TestStartMainProjectUpdateApplySingleFlightReturnsSameJob(t *testing.T) {
	t.Parallel()

	m := &Manager{}

	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	m.applyUpdateFn = func(context.Context) error {
		entered <- struct{}{}
		<-release
		return nil
	}
	m.updateCheckFn = func(context.Context) error { return nil }

	job1, accepted1, err := m.StartMainProjectUpdateApply(context.Background(), "manual")
	if err != nil {
		t.Fatalf("first StartMainProjectUpdateApply error: %v", err)
	}
	if !accepted1 {
		t.Fatalf("first accepted=%v want=true", accepted1)
	}

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting first apply to enter")
	}

	job2, accepted2, err := m.StartMainProjectUpdateApply(context.Background(), "manual")
	if err != nil {
		t.Fatalf("second StartMainProjectUpdateApply error: %v", err)
	}
	if accepted2 {
		t.Fatalf("second accepted=%v want=false", accepted2)
	}
	if job2.ID != job1.ID {
		t.Fatalf("job id mismatch second=%s first=%s", job2.ID, job1.ID)
	}
	if job2.State != UpdateApplyStateRunning {
		t.Fatalf("second state=%s want=%s", job2.State, UpdateApplyStateRunning)
	}

	close(release)
	m.Wait()
}

func TestStartMainProjectUpdateApplyFailureState(t *testing.T) {
	t.Parallel()

	m := &Manager{}
	m.applyUpdateFn = func(context.Context) error {
		return errors.New("apply failed for test")
	}
	m.updateCheckFn = func(context.Context) error { return nil }

	_, accepted, err := m.StartMainProjectUpdateApply(context.Background(), "manual")
	if err != nil {
		t.Fatalf("StartMainProjectUpdateApply error: %v", err)
	}
	if !accepted {
		t.Fatalf("accepted=%v want=true", accepted)
	}

	m.Wait()

	current := m.CurrentUpdateApplyJob()
	if current == nil {
		t.Fatalf("current update job should exist")
	}
	if current.State != UpdateApplyStateFailed {
		t.Fatalf("final state=%s want=%s", current.State, UpdateApplyStateFailed)
	}
	if current.FinishedAt == nil {
		t.Fatalf("finished_at should be set")
	}
	if !strings.Contains(current.Error, "apply failed for test") {
		t.Fatalf("error=%q should contain apply failure", current.Error)
	}
}
