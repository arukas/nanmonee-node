package worker

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	"nanmonee/node/internal/panel"
	"nanmonee/node/internal/probe"
	noderuntime "nanmonee/node/internal/runtime"
	"nanmonee/node/internal/traffic"
)

// Default intervals. The panel may negotiate different pull/push intervals; the
// sample interval is local and only bounds metering granularity.
const (
	DefaultPullInterval   = 60 * time.Second
	DefaultPushInterval   = 60 * time.Second
	DefaultSampleInterval = 10 * time.Second
	// requestTimeout bounds one panel round trip independently of the tick.
	requestTimeout = 20 * time.Second
	// shutdownReportTimeout bounds the final drain during shutdown.
	shutdownReportTimeout = 10 * time.Second
	// probeTickInterval is how often the worker checks for due probe targets.
	// Per-target intervals still decide whether a probe actually runs.
	probeTickInterval = 5 * time.Second
	// probeConcurrency bounds simultaneous measurements so a long target list
	// cannot open an unbounded number of sockets.
	probeConcurrency = 4
)

// Observer exposes the worker's own view for the control plane status message.
type Observer interface {
	Observation() Observation
}

// Observation is a point-in-time view the control plane can report.
type Observation struct {
	PanelHost      string
	LastPullAt     time.Time
	LastPushAt     time.Time
	LastError      string
	Rejected       bool
	PendingBatches int
	PendingMembers int
}

// Worker owns the panel side of the node: it is the only writer to the runtime
// while the panel is authoritative, and the only reporter of traffic.
type Worker struct {
	client  *panel.Client
	runtime *noderuntime.Runtime
	spool   *traffic.Spool

	pullInterval   time.Duration
	pushInterval   time.Duration
	sampleInterval time.Duration

	mu         sync.Mutex
	rejected   bool
	lastPullAt time.Time
	lastPushAt time.Time
	lastError  string

	configETag string
	usersETag  string
	hasConfig  bool
	hasUsers   bool

	// Probe targets are re-read from the panel each pull; the map records when
	// each target was last measured so the node honours its own interval.
	probeMu      sync.Mutex
	probeTargets []panel.ProbeTarget
	probeLastRun map[int64]time.Time

	// Cache the last fetched config and users; apply only after both pulls succeed.
	pendingConfig noderuntime.Config
	pendingUsers  []noderuntime.User
}

// Options configures a Worker.
type Options struct {
	Client  *panel.Client
	Runtime *noderuntime.Runtime
	Spool   *traffic.Spool
}

// New validates the wiring. All three collaborators are required: the worker is
// the only writer, so it must own both the runtime and the spool.
func New(options Options) (*Worker, error) {
	if options.Client == nil || options.Runtime == nil || options.Spool == nil {
		return nil, errors.New("the panel worker requires a client, a runtime, and a traffic spool")
	}
	return &Worker{
		client:         options.Client,
		runtime:        options.Runtime,
		spool:          options.Spool,
		pullInterval:   DefaultPullInterval,
		pushInterval:   DefaultPushInterval,
		sampleInterval: DefaultSampleInterval,
	}, nil
}

// Observation returns the current worker view.
func (w *Worker) Observation() Observation {
	w.mu.Lock()
	defer w.mu.Unlock()
	observation := Observation{
		PanelHost:      w.client.Host(),
		LastPullAt:     w.lastPullAt,
		LastPushAt:     w.lastPushAt,
		LastError:      w.lastError,
		Rejected:       w.rejected,
		PendingBatches: w.spool.Pending(),
		PendingMembers: w.spool.Total(),
	}
	return observation
}

func (w *Worker) setError(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err == nil {
		w.lastError = ""
		return
	}
	w.lastError = err.Error()
}

// Run performs the handshake and then services the pull, sample, and push
// schedules until ctx is canceled. It never returns a nil error silently.
func (w *Worker) Run(ctx context.Context) error {
	if err := w.handshake(ctx); err != nil {
		return err
	}
	if err := w.sync(ctx, true); err != nil {
		// The first snapshot must succeed; otherwise the node stays closed.
		return err
	}

	pull := time.NewTicker(w.pullInterval)
	defer pull.Stop()
	push := time.NewTicker(w.pushInterval)
	defer push.Stop()
	sample := time.NewTicker(w.sampleInterval)
	defer sample.Stop()
	// One tick drives every probe target; per-target intervals are enforced
	// against the last run rather than by a ticker each.
	probe := time.NewTicker(probeTickInterval)
	defer probe.Stop()

	for {
		select {
		case <-ctx.Done():
			return w.shutdown()
		case <-pull.C:
			// Errors are recorded, never fatal: the last good snapshot stays live.
			_ = w.sync(ctx, false)
			_ = w.refreshProbeTargets(ctx)
		case <-sample.C:
			_ = w.collect(ctx, false)
		case <-probe.C:
			// A probe failure must never disturb traffic reporting.
			_ = w.runProbes(ctx)
		case <-push.C:
			_ = w.collect(ctx, true)
		}
	}
}

func (w *Worker) handshake(ctx context.Context) error {
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	negotiated, err := w.client.Handshake(requestCtx)
	if err != nil {
		w.setError(err)
		return fmt.Errorf("panel handshake: %w", err)
	}
	if negotiated.Settings.PullInterval > 0 {
		w.pullInterval = time.Duration(negotiated.Settings.PullInterval) * time.Second
	}
	if negotiated.Settings.PushInterval > 0 {
		w.pushInterval = time.Duration(negotiated.Settings.PushInterval) * time.Second
	}
	log.Printf("panel handshake accepted by %s (pull %s, push %s)", w.client.Host(), w.pullInterval, w.pushInterval)
	return nil
}

// sync pulls config and users and applies them as one snapshot. Pulling is
// serialized: Run calls it from a single goroutine and never overlaps itself.
func (w *Worker) sync(ctx context.Context, initial bool) error {
	if err := w.pullConfig(ctx, initial); err != nil {
		return w.handleFailure(err)
	}
	if err := w.pullUsers(ctx, initial); err != nil {
		return w.handleFailure(err)
	}
	config, hasConfig := w.currentConfig()
	users, hasUsers := w.currentUsers()
	if !hasConfig || !hasUsers {
		return nil
	}
	if _, err := w.runtime.ApplyPanel(ctx, config, users); err != nil {
		w.setError(err)
		return fmt.Errorf("apply panel snapshot: %w", err)
	}
	w.mu.Lock()
	w.rejected = false
	w.lastPullAt = time.Now()
	w.mu.Unlock()
	w.runtime.ClearError()
	w.setError(nil)
	return nil
}

// handleFailure classifies a pull error. Explicit rejections revoke everything
// immediately but keep the queued traffic; outages keep the last authorization.
func (w *Worker) handleFailure(err error) error {
	if errors.Is(err, panel.ErrRejected) {
		w.mu.Lock()
		w.rejected = true
		w.configETag = ""
		w.usersETag = ""
		w.hasConfig = false
		w.hasUsers = false
		w.mu.Unlock()
		if _, revokeErr := w.runtime.RevokeAll("the panel revoked this node; all members are deauthorized"); revokeErr != nil {
			err = errors.Join(err, fmt.Errorf("revoke after panel rejection: %w", revokeErr))
		}
		w.setError(err)
		log.Printf("panel rejected this node; authorization revoked, queued traffic retained: %v", err)
		return err
	}
	if errors.Is(err, panel.ErrIncompatible) {
		// A protocol mismatch is not a transient failure. Stop authorizing.
		if _, revokeErr := w.runtime.RevokeAll("the panel and agent protocols do not match"); revokeErr != nil {
			err = errors.Join(err, fmt.Errorf("revoke after protocol mismatch: %w", revokeErr))
		}
		w.setError(err)
		return err
	}
	w.setError(err)
	w.runtime.RecordError(err.Error())
	return err
}

func (w *Worker) pullConfig(ctx context.Context, initial bool) error {
	w.mu.Lock()
	etag := w.configETag
	if initial {
		etag = ""
	}
	w.mu.Unlock()
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	snapshot, err := w.client.Config(requestCtx, etag)
	if err != nil {
		return err
	}
	if snapshot.NotModified {
		// A 304 is only meaningful when this process already holds the content.
		w.mu.Lock()
		ok := w.hasConfig
		w.mu.Unlock()
		if !ok {
			return fmt.Errorf("%w: the panel answered 304 without a cached config", panel.ErrTransient)
		}
		return nil
	}
	config, err := inboundConfig(snapshot.Config)
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.configETag = snapshot.ETag
	w.pendingConfig = config
	w.hasConfig = true
	w.mu.Unlock()
	return nil
}

func (w *Worker) pullUsers(ctx context.Context, initial bool) error {
	w.mu.Lock()
	etag := w.usersETag
	if initial {
		etag = ""
	}
	w.mu.Unlock()
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	snapshot, err := w.client.Users(requestCtx, etag)
	if err != nil {
		return err
	}
	if snapshot.NotModified {
		w.mu.Lock()
		ok := w.hasUsers
		w.mu.Unlock()
		if !ok {
			return fmt.Errorf("%w: the panel answered 304 without cached users", panel.ErrTransient)
		}
		return nil
	}
	users := make([]noderuntime.User, 0, len(snapshot.Members))
	for _, member := range snapshot.Members {
		users = append(users, noderuntime.User{MemberID: member.MemberID, UUID: member.UUID})
	}
	w.mu.Lock()
	w.usersETag = snapshot.ETag
	w.pendingUsers = users
	w.hasUsers = true
	w.mu.Unlock()
	return nil
}

// inboundConfig maps the panel document onto the runtime's protocol union. A
// protocol the agent did not ask for is a hard failure, never a downgrade.
func inboundConfig(document panel.InboundConfig) (noderuntime.Config, error) {
	switch document.Protocol {
	case noderuntime.ProtocolVless:
		return noderuntime.VlessRuntimeConfig(noderuntime.VlessConfig{
			Listen:            document.Vless.Listen,
			Port:              document.Vless.Port,
			ServerName:        document.Vless.ServerName,
			HandshakeServer:   document.Vless.HandshakeServer,
			HandshakePort:     document.Vless.HandshakePort,
			RealityPrivateKey: document.Vless.PrivateKey,
			RealityShortID:    document.Vless.ShortID,
		}), nil
	case noderuntime.ProtocolHysteria2:
		return noderuntime.Hysteria2RuntimeConfig(noderuntime.Hysteria2Config{
			Listen:          document.Hysteria2.Listen,
			Port:            document.Hysteria2.Port,
			ServerName:      document.Hysteria2.ServerName,
			CertificatePath: document.Hysteria2.CertificatePath,
			PrivateKeyPath:  document.Hysteria2.PrivateKeyPath,
		}), nil
	case noderuntime.ProtocolTuic:
		return noderuntime.TuicRuntimeConfig(noderuntime.TuicConfig{
			Listen:          document.Tuic.Listen,
			Port:            document.Tuic.Port,
			ServerName:      document.Tuic.ServerName,
			CertificatePath: document.Tuic.CertificatePath,
			PrivateKeyPath:  document.Tuic.PrivateKeyPath,
		}), nil
	case noderuntime.ProtocolAnytls:
		return noderuntime.AnytlsRuntimeConfig(noderuntime.AnytlsConfig{
			Listen:          document.Anytls.Listen,
			Port:            document.Anytls.Port,
			ServerName:      document.Anytls.ServerName,
			CertificatePath: document.Anytls.CertificatePath,
			PrivateKeyPath:  document.Anytls.PrivateKeyPath,
		}), nil
	default:
		return noderuntime.Config{}, fmt.Errorf("%w: the panel offered protocol %q", panel.ErrIncompatible, document.Protocol)
	}
}

func (w *Worker) currentConfig() (noderuntime.Config, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.pendingConfig, w.hasConfig
}

func (w *Worker) currentUsers() ([]noderuntime.User, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]noderuntime.User(nil), w.pendingUsers...), w.hasUsers
}

// collect persists counters; only a report tick (or a full spool) sends them.
func (w *Worker) collect(ctx context.Context, report bool) error {
	usage, err := w.runtime.Usage()
	if err != nil {
		w.setError(err)
		return err
	}
	// Bound the entire drain, not each of its up to 16 requests separately.
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	send := func(batch panel.TrafficBatch) error {
		return w.client.ReportTrafficBatch(requestCtx, batch)
	}
	measured := make(map[int][2]int64, len(usage.Members))
	for memberID, counters := range usage.Members {
		if memberID <= 0 || memberID > math.MaxInt {
			err := fmt.Errorf("%w: member ID %d is out of range", traffic.ErrSampleInvalid, memberID)
			w.setError(err)
			return err
		}
		measured[int(memberID)] = counters
	}
	if report {
		err = w.spool.Report(measured, usage.RuntimeID, send)
	} else {
		err = w.spool.Sample(measured, usage.RuntimeID)
		if errors.Is(err, traffic.ErrSpoolFull) {
			err = w.spool.Report(measured, usage.RuntimeID, send)
		}
	}
	if err != nil {
		if errors.Is(err, panel.ErrRejected) {
			return w.handleFailure(err)
		}
		w.setError(err)
		if !traffic.Persisted(err) {
			// The next cumulative sample retries the unpersisted delta.
			log.Printf("traffic sample not persisted: %v", err)
		}
		return err
	}
	if !report {
		return nil
	}
	w.mu.Lock()
	w.lastPushAt = time.Now()
	w.mu.Unlock()
	w.setError(nil)
	return nil
}

// shutdown captures one final sample and makes a bounded attempt to drain.
func (w *Worker) shutdown() error {
	closeErr := w.runtime.Close()
	ctx, cancel := context.WithTimeout(context.Background(), shutdownReportTimeout)
	defer cancel()
	return errors.Join(closeErr, w.collect(ctx, true))
}

// refreshProbeTargets reloads the address list the panel wants measured.
func (w *Worker) refreshProbeTargets(ctx context.Context) error {
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	targets, err := w.client.ProbeTargets(requestCtx)
	if err != nil {
		w.setError(err)
		return err
	}

	w.probeMu.Lock()
	w.probeTargets = targets
	if w.probeLastRun == nil {
		w.probeLastRun = make(map[int64]time.Time)
	}
	// Drop timing state for targets the panel removed, so a re-added target with
	// the same ID starts fresh.
	live := make(map[int64]time.Time, len(targets))
	for _, target := range targets {
		if last, ok := w.probeLastRun[target.ID]; ok {
			live[target.ID] = last
		}
	}
	w.probeLastRun = live
	w.probeMu.Unlock()

	return nil
}

// runProbes measures every target whose interval has elapsed and reports the
// batch. Measurement failures are data, not worker errors: they are sent to the
// panel as a sample with an error and never stop the loop.
func (w *Worker) runProbes(ctx context.Context) error {
	w.probeMu.Lock()
	due := make([]panel.ProbeTarget, 0, len(w.probeTargets))
	now := time.Now()
	for _, target := range w.probeTargets {
		interval := time.Duration(target.IntervalSeconds) * time.Second
		if interval <= 0 {
			interval = time.Minute
		}
		if last, ok := w.probeLastRun[target.ID]; ok && now.Sub(last) < interval {
			continue
		}
		// Mark before measuring so a slow probe cannot be started twice.
		w.probeLastRun[target.ID] = now
		due = append(due, target)
	}
	w.probeMu.Unlock()

	if len(due) == 0 {
		return nil
	}

	results := make([]panel.ProbeSample, len(due))
	semaphore := make(chan struct{}, probeConcurrency)
	var group sync.WaitGroup
	for index, target := range due {
		group.Add(1)
		go func(index int, target panel.ProbeTarget) {
			defer group.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			probeType, ok := probeTypeOf(target.Type)
			if !ok {
				results[index] = panel.ProbeSample{
					TargetID:  target.ID,
					Error:     "unsupported probe type",
					SampledAt: time.Now().Unix(),
				}
				return
			}

			measured := probe.Measure(ctx, probe.Target{
				ID:      target.ID,
				Type:    probeType,
				Host:    target.Host,
				Port:    target.Port,
				Timeout: time.Duration(target.TimeoutMS) * time.Millisecond,
			})

			sample := panel.ProbeSample{
				TargetID:  measured.TargetID,
				LatencyMS: measured.LatencyMS,
				Error:     measured.Err,
				SampledAt: measured.SampledAt.Unix(),
			}
			results[index] = sample
		}(index, target)
	}
	group.Wait()

	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	if err := w.client.ReportProbeSamples(requestCtx, panel.ProbeSamples{Results: results}); err != nil {
		w.setError(err)
		return err
	}

	return nil
}

// probeTypeOf maps the panel's wire value onto the probe package's type.
func probeTypeOf(value string) (probe.Type, bool) {
	switch probe.Type(value) {
	case probe.TypeICMP:
		return probe.TypeICMP, true
	case probe.TypeTCP:
		return probe.TypeTCP, true
	case probe.TypeHTTP:
		return probe.TypeHTTP, true
	case probe.TypeHTTPS:
		return probe.TypeHTTPS, true
	default:
		return "", false
	}
}
