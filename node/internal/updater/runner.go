package updater

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Version is the updater's own version, reported to the panel so an operator can
// tell which hosts still run an updater that predates a change.
const Version = "0.11.0"

// nodeUnitPrefix is the systemd instance prefix the installer creates.
const nodeUnitPrefix = "nanmonee-node@"

// restartTimeout bounds one unit restart; a hung unit must not stall the rest.
const restartTimeout = 60 * time.Second

// Runner is one upgrade execution. Fields are exported so the tests can drive it
// with a fake panel and a temporary release directory.
type Runner struct {
	Client     *Client
	Config     Config
	ReleaseDir string
	// Restart restarts one unit and returns its error. It is a field so a test
	// can verify the whole plan without touching systemd.
	Restart func(unit string) error
	// HealthCheck confirms the unit is running after a restart.
	HealthCheck func(unit string) error
	Log         *log.Logger
}

// NewRunner builds the production wiring: systemctl is the only external
// command the updater ever runs, and it always names an explicit unit.
func NewRunner(client *Client, config Config) *Runner {
	logger := log.New(os.Stdout, "updater: ", log.LstdFlags|log.LUTC)

	return &Runner{
		Client:     client,
		Config:     config,
		ReleaseDir: config.ReleaseDir,
		Restart:    systemctlRestart,
		HealthCheck: func(unit string) error {
			// Not --quiet: the state string ("failed", "activating", "inactive")
			// is the only part of this answer an operator can act on.
			output, err := exec.Command("systemctl", "is-active", unit).CombinedOutput()
			state := strings.TrimSpace(string(output))
			if err != nil {
				return fmt.Errorf("%s is not active (%s)", unit, state)
			}
			if state != "active" {
				return fmt.Errorf("%s is not active (%s)", unit, state)
			}
			return nil
		},
		Log: logger,
	}
}

// Run performs one check-and-maybe-upgrade cycle and returns the result it
// reported (nil when there was nothing to do).
func (r *Runner) Run() (*Result, error) {
	currentVersion, currentRelease, _ := CurrentVersion(r.ReleaseDir)

	payload := CheckRequest{
		UpdaterVersion: Version,
		CurrentVersion: optional(currentVersion),
		CurrentRelease: optional(currentRelease),
	}

	instruction, err := r.Client.Check(payload)
	if err != nil {
		return nil, err
	}
	r.Log.Printf("panel answered %q (%s)", instruction.Action, instruction.Reason)

	if !instruction.Install() || instruction.RequestID == nil {
		return nil, nil
	}

	result := r.install(instruction, currentRelease)
	return result, nil
}

// install stages, activates, restarts and rolls back on failure. The returned
// result is what the next cycle reports to the panel.
func (r *Runner) install(instruction Instruction, previousRelease string) *Result {
	version := instruction.Version
	result := &Result{RequestID: *instruction.RequestID, Outcome: "failed"}

	release, err := r.Client.Stage(r.ReleaseDir, version, instruction.Artifacts)
	if err != nil {
		r.Log.Printf("stage %s: %v", version, err)
		result.Error = optional(err.Error())
		return result
	}
	r.Log.Printf("staged %s at %s", version, release.Dir)

	if err := Activate(r.ReleaseDir, release); err != nil {
		r.Log.Printf("activate %s: %v", version, err)
		result.Error = optional(err.Error())
		return result
	}

	restarted, err := r.restartAll(instruction.RestartUnits)
	if err != nil {
		r.Log.Printf("restart after %s failed: %v", version, err)
		result.Error = optional(err.Error())
		// Put the host back on the release that was working. A rollback that also
		// fails is reported, because the host is then in a state an operator must
		// look at by hand.
		if rollbackErr := r.rollback(previousRelease, restarted); rollbackErr != nil {
			r.Log.Printf("rollback failed: %v", rollbackErr)
			result.Error = optional(fmt.Sprintf("%v; rollback failed: %v", err, rollbackErr))
		}
		return result
	}

	result.Outcome = "succeeded"
	result.InstalledVersion = optional(version)
	r.Log.Printf("installed %s and restarted %d unit(s)", version, len(instruction.RestartUnits))

	return result
}

// restartAll restarts each unit in turn, stopping at the first failure. It
// returns the units it already restarted so a rollback can undo them too.
func (r *Runner) restartAll(units []string) ([]string, error) {
	restarted := make([]string, 0, len(units))
	for _, unit := range units {
		// The panel names the units, so validate the shape before handing the
		// string to systemctl: no spaces, no shell metacharacters, only this
		// project's own instances.
		if !validUnit(unit) {
			return restarted, fmt.Errorf("the panel named an unusable unit %q", unit)
		}
		if err := r.Restart(unit); err != nil {
			return restarted, err
		}
		restarted = append(restarted, unit)
		if err := r.HealthCheck(unit); err != nil {
			return restarted, err
		}
	}

	return restarted, nil
}

// rollback restores the previous release and restarts whatever came up, so the
// host never sits on a binary that would not start.
func (r *Runner) rollback(previousRelease string, restarted []string) error {
	if previousRelease == "" {
		// Nothing was active before: leaving current alone is safer than pointing
		// it at a guessed path.
		return errors.New("the host had no previous release")
	}
	if err := Restore(r.ReleaseDir, previousRelease); err != nil {
		return err
	}
	var failures []string
	for _, unit := range restarted {
		if err := r.Restart(unit); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}

	return nil
}

// Report sends the outcome to the panel. A failure here is not fatal: the next
// cycle re-reports because the panel keeps the request outstanding until the
// version it sees matches.
func (r *Runner) Report(result *Result) error {
	currentVersion, currentRelease, _ := CurrentVersion(r.ReleaseDir)
	_, err := r.Client.Check(CheckRequest{
		UpdaterVersion: Version,
		CurrentVersion: optional(currentVersion),
		CurrentRelease: optional(currentRelease),
		Result:         result,
	})
	if err != nil {
		return fmt.Errorf("report the upgrade result: %w", err)
	}

	return nil
}

func systemctlRestart(unit string) error {
	command := exec.Command("systemctl", "restart", unit)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		return fmt.Errorf("restart %s: %w", unit, err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("restart %s: %w", unit, err)
		}
		return nil
	case <-time.After(restartTimeout):
		_ = command.Process.Kill()
		return fmt.Errorf("restart %s timed out", unit)
	}
}

// validUnit accepts only this project's own instance names.
func validUnit(unit string) bool {
	if !strings.HasPrefix(unit, nodeUnitPrefix) || !strings.HasSuffix(unit, ".service") {
		return false
	}
	instance := strings.TrimSuffix(strings.TrimPrefix(unit, nodeUnitPrefix), ".service")
	if instance == "" {
		return false
	}
	for _, character := range instance {
		if character < '0' || character > '9' {
			return false
		}
	}

	return true
}

func optional(value string) *string {
	if value == "" {
		return nil
	}

	return &value
}

// ReleaseDirOf reports where a config's releases live, so callers do not repeat
// the default.
func ReleaseDirOf(config Config) string {
	return filepath.Clean(config.ReleaseDir)
}
