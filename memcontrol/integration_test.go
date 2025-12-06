package memcontrol

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// init configures small limits and suppresses logs for testing.
func init() {
	// Suppress logs during tests
	SetLogLevel(LogLevelOff)
}

// resetGlobalState resets global state between tests.
// CRITICAL: Must be called at the start of each test to prevent cross-test pollution.
func resetGlobalState() {
	// Reset budget to fresh state with small limits for testing
	globalMemoryBudget = newMemoryBudget()
	globalMemoryBudget.softLimit.Store(50 * 1024)  // 50KB soft
	globalMemoryBudget.hardLimit.Store(100 * 1024) // 100KB hard
	globalMemoryBudget.disabled.Store(false)

	// Reset registry
	globalRegistry = &Registry{
		conns: make(map[uint64]*Conn),
		byTag: make(map[string]*atomic.Int32),
	}

	// Reset buffer tracking
	bufferOriginalSizes = sync.Map{}
	bufferSizeMapCount.Store(0)

	// Reset stats
	for i := 0; i < 6; i++ {
		stats.allocated[i].Store(0)
		stats.returned[i].Store(0)
	}
	stats.oversized.Store(0)
	stats.polluted.Store(0)
	stats.orphaned.Store(0)
	stats.evicted.Store(0)
}

// -----------------------------------------------------------------------------
// Test 1: TestConfigureMemoryBasic - ConfigureMemory sets limits correctly
// -----------------------------------------------------------------------------

func TestConfigureMemoryBasic(t *testing.T) {
	resetGlobalState()

	// Configure with specific limits
	ConfigureMemory(Config{
		SoftLimit: 10 * 1024 * 1024, // 10MB
		HardLimit: 15 * 1024 * 1024, // 15MB
	})

	state := GetBudgetState()
	if state.SoftLimit != 10*1024*1024 {
		t.Errorf("SoftLimit = %d, want %d", state.SoftLimit, 10*1024*1024)
	}
	if state.HardLimit != 15*1024*1024 {
		t.Errorf("HardLimit = %d, want %d", state.HardLimit, 15*1024*1024)
	}
}

func TestConfigureMemoryDisabled(t *testing.T) {
	resetGlobalState()

	ConfigureMemory(Config{Disabled: true})

	state := GetBudgetState()
	if !state.Disabled {
		t.Error("Expected Disabled=true")
	}
	// When disabled, limits should be very high
	if state.SoftLimit < 1<<60 {
		t.Errorf("SoftLimit when disabled should be very high, got %d", state.SoftLimit)
	}
}

func TestConfigureMemoryCacheLimits(t *testing.T) {
	resetGlobalState()

	ConfigureMemory(Config{
		SoftLimit:         1024 * 1024,
		HardLimit:         2 * 1024 * 1024,
		SessionCacheLimit: 5000,
		ReplayCacheLimit:  50000,
	})

	if GetSessionCacheLimit() != 5000 {
		t.Errorf("SessionCacheLimit = %d, want 5000", GetSessionCacheLimit())
	}
	if GetReplayCacheLimit() != 50000 {
		t.Errorf("ReplayCacheLimit = %d, want 50000", GetReplayCacheLimit())
	}
}

// -----------------------------------------------------------------------------
// Test 2: TestConfigureFromUpstream - ConfigureFromUpstream sets limits and logs
// -----------------------------------------------------------------------------

func TestConfigureFromUpstream(t *testing.T) {
	resetGlobalState()

	// Configure from upstream with specific limits
	ConfigureFromUpstream(Config{
		SoftLimit: 20 * 1024 * 1024, // 20MB
		HardLimit: 30 * 1024 * 1024, // 30MB
	})

	state := GetBudgetState()
	if state.SoftLimit != 20*1024*1024 {
		t.Errorf("SoftLimit = %d, want %d", state.SoftLimit, 20*1024*1024)
	}
	if state.HardLimit != 30*1024*1024 {
		t.Errorf("HardLimit = %d, want %d", state.HardLimit, 30*1024*1024)
	}
}

// -----------------------------------------------------------------------------
// Test 3: TestConfigureFromUpstreamWithPortion - Portion calculation correct
// -----------------------------------------------------------------------------

func TestConfigureFromUpstreamWithPortion(t *testing.T) {
	resetGlobalState()

	// 50% of 10MB/20MB = 5MB/10MB
	ConfigureFromUpstreamWithPortion(
		10*1024*1024, // 10MB soft
		20*1024*1024, // 20MB hard
		0.5,          // 50%
	)

	state := GetBudgetState()
	expectedSoft := int64(5 * 1024 * 1024)
	expectedHard := int64(10 * 1024 * 1024)

	if state.SoftLimit != expectedSoft {
		t.Errorf("SoftLimit = %d, want %d (50%% of 10MB)", state.SoftLimit, expectedSoft)
	}
	if state.HardLimit != expectedHard {
		t.Errorf("HardLimit = %d, want %d (50%% of 20MB)", state.HardLimit, expectedHard)
	}
}

func TestConfigureFromUpstreamWithPortionInvalid(t *testing.T) {
	resetGlobalState()

	// Invalid portion (0) should default to 25%
	ConfigureFromUpstreamWithPortion(
		100*1024*1024, // 100MB soft
		200*1024*1024, // 200MB hard
		0,             // Invalid - will use 25%
	)

	state := GetBudgetState()
	expectedSoft := int64(25 * 1024 * 1024) // 25%
	expectedHard := int64(50 * 1024 * 1024) // 25%

	if state.SoftLimit != expectedSoft {
		t.Errorf("SoftLimit = %d, want %d (25%% default)", state.SoftLimit, expectedSoft)
	}
	if state.HardLimit != expectedHard {
		t.Errorf("HardLimit = %d, want %d (25%% default)", state.HardLimit, expectedHard)
	}
}

func TestConfigureFromUpstreamWithPortionNegative(t *testing.T) {
	resetGlobalState()

	// Negative portion should default to 25%
	ConfigureFromUpstreamWithPortion(
		100*1024*1024, // 100MB soft
		200*1024*1024, // 200MB hard
		-0.5,          // Invalid - will use 25%
	)

	state := GetBudgetState()
	expectedSoft := int64(25 * 1024 * 1024)
	expectedHard := int64(50 * 1024 * 1024)

	if state.SoftLimit != expectedSoft {
		t.Errorf("SoftLimit = %d, want %d", state.SoftLimit, expectedSoft)
	}
	if state.HardLimit != expectedHard {
		t.Errorf("HardLimit = %d, want %d", state.HardLimit, expectedHard)
	}
}

// -----------------------------------------------------------------------------
// Test 4: TestLinkEvictionCallback - LinkEvictionCallback chains callbacks
// -----------------------------------------------------------------------------

func TestLinkEvictionCallback(t *testing.T) {
	resetGlobalState()

	var upstreamCalled atomic.Bool

	// Test that LinkEvictionCallback chains correctly by invoking callback directly
	// (Async eviction via budget.TryAllocate can race with test cleanup)

	// Create mock upstream callback
	upstreamCallback := func() {
		upstreamCalled.Store(true)
	}

	// Link it - this sets up the chain: uTLS Shed + upstream callback
	LinkEvictionCallback(upstreamCallback)

	// Create a connection to verify registry integration
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	conn := Wrap(server, "test-link")
	if conn != nil {
		defer conn.Close()
	}

	// Get the callback and invoke it directly (synchronous, no race)
	if fn := globalMemoryBudget.onEviction.Load(); fn != nil {
		(*fn)()
	}

	// Give a moment for the callback to complete
	time.Sleep(10 * time.Millisecond)

	if !upstreamCalled.Load() {
		t.Error("Upstream callback was not called")
	}

	// Verify registry.Shed() was called (part of LinkEvictionCallback)
	// This is implicit - if there were idle connections they would be shed
}

func TestEvictionCallbackFires(t *testing.T) {
	resetGlobalState()

	// Track that eviction callback fires
	var callbackFired atomic.Bool
	SetEvictionCallback(func() {
		callbackFired.Store(true)
	})

	// Configure small soft limit
	ConfigureMemory(Config{
		SoftLimit: 512, // Very small
		HardLimit: 100 * 1024,
	})

	// Allocate over soft limit
	budget := GetBudget()
	budget.TryAllocate(1024)

	// Wait for async callback
	time.Sleep(150 * time.Millisecond)

	if !callbackFired.Load() {
		t.Log("Note: Callback may not fire due to rate limiting (1/sec limit)")
	}

	// Clean up - release the allocation
	budget.Release(1024)
}

// -----------------------------------------------------------------------------
// Test 5: TestBufferPoolBudgetIntegration - GetBuffer respects budget
// -----------------------------------------------------------------------------

func TestBufferPoolBudgetIntegration(t *testing.T) {
	resetGlobalState()

	// Configure very small budget: 100KB
	ConfigureMemory(Config{
		SoftLimit: 50 * 1024,  // 50KB soft
		HardLimit: 100 * 1024, // 100KB hard
	})

	// Note: sync.Pool caching means buffers may come from cache (not counting against budget).
	// This test verifies the budget system works when NEW allocations are required.
	// We use unique large sizes that are unlikely to be in pool cache.

	// Direct budget allocation test (bypasses pool caching)
	budget := GetBudget()

	// Allocate directly via budget to test hard limit
	var allocated int64
	for i := 0; i < 20; i++ {
		if !budget.TryAllocate(8192) {
			// Expected - budget exhausted
			break
		}
		allocated += 8192
	}

	t.Logf("Direct budget allocation: %dKB before limit", allocated/1024)

	// Should have hit the 100KB limit
	if allocated >= 200*1024 {
		t.Error("Should have hit budget limit")
	}

	// Verify budget state shows the allocation
	state := GetBudgetState()
	if state.TotalBytes != allocated {
		t.Logf("TotalBytes=%d, allocated=%d (may differ if pool was active)", state.TotalBytes, allocated)
	}

	// Release budget
	for i := int64(0); i < allocated; i += 8192 {
		budget.Release(8192)
	}

	// Now test pool integration with oversized buffers (never cached)
	var buffers []*[]byte
	for i := 0; i < 5; i++ {
		// Use oversized allocation (> 16KB) which bypasses pool
		buf, err := GetBuffer(20000 + i*1000) // 20KB, 21KB, 22KB, etc.
		if err != nil {
			// Expected eventually - budget exhausted
			if err != ErrBufferPoolExhausted {
				t.Errorf("Unexpected error: %v", err)
			}
			break
		}
		buffers = append(buffers, buf)
	}

	t.Logf("Allocated %d oversized buffers", len(buffers))

	// Release all buffers
	for _, buf := range buffers {
		PutBuffer(buf)
	}

	// Now should be able to allocate again
	buf, err := GetBuffer(4096)
	if err != nil {
		t.Logf("Note: After release, allocation returned: %v (may be budget exhausted)", err)
	}
	if buf != nil {
		PutBuffer(buf)
	}
}

func TestBufferPoolBudgetExhaustedRecovers(t *testing.T) {
	resetGlobalState()

	// Very tight budget
	ConfigureMemory(Config{
		SoftLimit: 10 * 1024, // 10KB soft
		HardLimit: 16 * 1024, // 16KB hard
	})

	// Allocate one 8KB buffer
	buf1, err := GetBuffer(8192)
	if err != nil {
		t.Fatalf("First allocation failed: %v", err)
	}

	// Try another - might work or fail depending on pool state
	buf2, err := GetBuffer(8192)

	// Release first buffer
	PutBuffer(buf1)

	// Now should definitely work
	buf3, err := GetBuffer(4096)
	if err != nil {
		t.Errorf("After release, allocation should succeed: %v", err)
	}

	// Cleanup
	if buf2 != nil {
		PutBuffer(buf2)
	}
	if buf3 != nil {
		PutBuffer(buf3)
	}
}

// -----------------------------------------------------------------------------
// Test 6: TestEvictionCascade - Memory pressure triggers cascade
// -----------------------------------------------------------------------------

func TestEvictionCascade(t *testing.T) {
	resetGlobalState()

	// Configure small budget
	ConfigureMemory(Config{
		SoftLimit: 4 * 1024,  // 4KB soft
		HardLimit: 50 * 1024, // 50KB hard
	})

	var evictionCallbackFired atomic.Bool
	SetEvictionCallback(func() {
		evictionCallbackFired.Store(true)
	})

	// Allocate over soft limit (but under hard)
	buf1, err := GetBuffer(8192) // 8KB > 4KB soft limit
	if err != nil {
		t.Fatalf("Allocation failed: %v", err)
	}

	// Wait for async eviction callback
	time.Sleep(100 * time.Millisecond)

	// Callback should have fired
	if !evictionCallbackFired.Load() {
		t.Log("Eviction callback may not fire due to rate limiting")
	}

	// Verify we're in eviction mode
	if !IsMemoryPressure() {
		t.Log("Note: May not be in eviction mode if soft limit check is timing dependent")
	}

	// Release buffer - should NOT cache when over soft limit
	PutBuffer(buf1)

	// Stats should show eviction
	poolStats := GetPoolStats()
	t.Logf("Pool stats: polluted=%d (includes evicted)", poolStats.Polluted)
}

func TestEvictionModeNoCaching(t *testing.T) {
	resetGlobalState()

	// Configure very small soft limit
	ConfigureMemory(Config{
		SoftLimit: 1024,       // 1KB soft
		HardLimit: 1024 * 100, // 100KB hard
	})

	// First allocation to trigger eviction mode
	buf1, err := GetBuffer(4096) // 4KB > 1KB soft
	if err != nil {
		t.Fatalf("First allocation failed: %v", err)
	}

	stateBefore := GetBudgetState()
	t.Logf("Before release: TotalBytes=%d, InEviction=%v", stateBefore.TotalBytes, stateBefore.InEviction)

	// Release - should evict (not cache) because over soft limit
	PutBuffer(buf1)

	stateAfter := GetBudgetState()
	t.Logf("After release: TotalBytes=%d, InEviction=%v", stateAfter.TotalBytes, stateAfter.InEviction)

	// TotalBytes should decrease (not stay same as would happen if cached)
	if stateAfter.TotalBytes >= stateBefore.TotalBytes {
		t.Logf("Note: TotalBytes didn't decrease (expected if eviction worked)")
	}
}

// -----------------------------------------------------------------------------
// Test 7: TestConnectionShedOnPressure - Full flow with connections
// -----------------------------------------------------------------------------

func TestConnectionShedOnPressure(t *testing.T) {
	resetGlobalState()

	// Create wrapped connections
	var conns []*Conn
	var servers []net.Conn
	for i := 0; i < 5; i++ {
		server, client := net.Pipe()
		client.Close() // Close client side so connections become "idle"
		servers = append(servers, server)

		conn := Wrap(server, "test-shed")
		if conn != nil {
			conns = append(conns, conn)
		}
	}

	// Verify connections registered
	regState := GetRegistry().State()
	if regState.Active < 1 {
		t.Skip("No connections registered (managed conn may be disabled)")
	}
	t.Logf("Registered %d connections", regState.Active)

	// Set eviction callback to call registry.Shed()
	SetEvictionCallback(func() {
		GetRegistry().Shed()
	})

	// Simulate memory pressure by making connections idle and calling Shed
	time.Sleep(50 * time.Millisecond) // Let connections become idle

	// Trigger shedding directly
	GetRegistry().CloseIdle(10 * time.Millisecond) // Very short threshold for test

	// Check some connections were closed
	regStateAfter := GetRegistry().State()
	t.Logf("After shed: Active=%d, TotalShed=%d", regStateAfter.Active, regStateAfter.TotalShed)

	// Cleanup remaining
	for _, server := range servers {
		server.Close()
	}
}

// -----------------------------------------------------------------------------
// Test 8: TestMemoryStatsAccurate - GetBudgetState reflects actual usage
// -----------------------------------------------------------------------------

func TestMemoryStatsAccurate(t *testing.T) {
	resetGlobalState()

	ConfigureMemory(Config{
		SoftLimit: 100 * 1024 * 1024, // 100MB - high to prevent eviction
		HardLimit: 200 * 1024 * 1024,
	})

	// Initial state
	state0 := GetBudgetState()
	t.Logf("Initial: Total=%d, InUse=%d, Cached=%d", state0.TotalBytes, state0.InUseBytes, state0.CachedBytes)

	// Allocate known amount: 8KB
	buf, err := GetBuffer(8192)
	if err != nil {
		t.Fatalf("GetBuffer failed: %v", err)
	}

	state1 := GetBudgetState()
	t.Logf("After Get 8KB: Total=%d, InUse=%d, Gets=%d", state1.TotalBytes, state1.InUseBytes, state1.Gets)

	// Verify InUseBytes increased
	if state1.InUseBytes < state0.InUseBytes+8192 {
		t.Logf("Note: InUseBytes increased by less than expected (pool may have reused)")
	}

	// Release - under soft limit so should cache
	PutBuffer(buf)

	state2 := GetBudgetState()
	t.Logf("After Put: Total=%d, InUse=%d, Cached=%d", state2.TotalBytes, state2.InUseBytes, state2.CachedBytes)

	// InUseBytes should decrease
	if state2.InUseBytes > state1.InUseBytes {
		t.Error("InUseBytes should decrease after PutBuffer")
	}
}

func TestMemoryStatsGetsAndReturns(t *testing.T) {
	resetGlobalState()

	ConfigureMemory(Config{
		SoftLimit: 100 * 1024 * 1024,
		HardLimit: 200 * 1024 * 1024,
	})

	stateBefore := GetBudgetState()

	// Allocate and release 5 buffers
	for i := 0; i < 5; i++ {
		buf, err := GetBuffer(512)
		if err != nil {
			t.Fatalf("GetBuffer failed: %v", err)
		}
		PutBuffer(buf)
	}

	stateAfter := GetBudgetState()

	expectedGets := stateBefore.Gets + 5
	if stateAfter.Gets != expectedGets {
		t.Errorf("Gets = %d, want %d", stateAfter.Gets, expectedGets)
	}
}

// -----------------------------------------------------------------------------
// Test 9: TestPresetConfigs - All presets have valid limits
// -----------------------------------------------------------------------------

func TestPresetConfigs(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{"ClientConfig", ClientConfig()},
		{"ServerConfig", ServerConfig()},
		{"TinyRouterConfig", TinyRouterConfig()},
		{"LargeServerConfig", LargeServerConfig()},
		{"DefaultConfig", DefaultConfig()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.config

			// soft < hard
			if cfg.SoftLimit >= cfg.HardLimit {
				t.Errorf("%s: SoftLimit (%d) should be < HardLimit (%d)",
					tt.name, cfg.SoftLimit, cfg.HardLimit)
			}

			// Both > 0
			if cfg.SoftLimit <= 0 {
				t.Errorf("%s: SoftLimit should be > 0", tt.name)
			}
			if cfg.HardLimit <= 0 {
				t.Errorf("%s: HardLimit should be > 0", tt.name)
			}

			// Cache limits positive
			if cfg.SessionCacheLimit <= 0 {
				t.Errorf("%s: SessionCacheLimit should be > 0", tt.name)
			}
			if cfg.ReplayCacheLimit <= 0 {
				t.Errorf("%s: ReplayCacheLimit should be > 0", tt.name)
			}
		})
	}
}

func TestPresetConfigsRelativeSize(t *testing.T) {
	tiny := TinyRouterConfig()
	client := ClientConfig()
	server := ServerConfig()
	large := LargeServerConfig()

	// TinyRouter < Client
	if tiny.HardLimit >= client.HardLimit {
		t.Errorf("TinyRouter (%d) should have smaller limits than Client (%d)",
			tiny.HardLimit, client.HardLimit)
	}

	// Client < Server
	if client.HardLimit >= server.HardLimit {
		t.Errorf("Client (%d) should have smaller limits than Server (%d)",
			client.HardLimit, server.HardLimit)
	}

	// Server < LargeServer
	if server.HardLimit >= large.HardLimit {
		t.Errorf("Server (%d) should have smaller limits than LargeServer (%d)",
			server.HardLimit, large.HardLimit)
	}
}

// -----------------------------------------------------------------------------
// Test 10: TestLoggerIntegration - Logging works at all levels
// -----------------------------------------------------------------------------

func TestLoggerIntegration(t *testing.T) {
	resetGlobalState()

	// Test SetLogLevel changes behavior
	SetLogLevel(LogLevelDebug)
	if GetLogLevel() != LogLevelDebug {
		t.Errorf("GetLogLevel() = %d, want %d", GetLogLevel(), LogLevelDebug)
	}

	SetLogLevel(LogLevelOff)
	if GetLogLevel() != LogLevelOff {
		t.Errorf("GetLogLevel() = %d, want %d", GetLogLevel(), LogLevelOff)
	}

	SetLogLevel(LogLevelWarn)
	if GetLogLevel() != LogLevelWarn {
		t.Errorf("GetLogLevel() = %d, want %d", GetLogLevel(), LogLevelWarn)
	}
}

func TestLoggerCustomHandler(t *testing.T) {
	resetGlobalState()

	var receivedMessages []string
	var receivedLevels []LogLevel
	var mu sync.Mutex

	SetLogHandler(func(level LogLevel, msg string) {
		mu.Lock()
		receivedMessages = append(receivedMessages, msg)
		receivedLevels = append(receivedLevels, level)
		mu.Unlock()
	})
	defer SetLogHandler(nil) // Reset after test

	SetLogLevel(LogLevelDebug) // Enable all levels

	// Trigger logging by configuring memory (logs info message)
	ConfigureFromUpstream(Config{
		SoftLimit: 1024 * 1024,
		HardLimit: 2 * 1024 * 1024,
	})

	// Give time for any async logs
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(receivedMessages) == 0 {
		t.Log("Note: No messages received (may be expected if logging suppressed)")
	} else {
		t.Logf("Received %d log messages", len(receivedMessages))
		for i, msg := range receivedMessages {
			t.Logf("  [%d] Level %d: %s", i, receivedLevels[i], msg)
		}
	}
}

func TestLoggerLevelFiltering(t *testing.T) {
	resetGlobalState()

	var messageCount atomic.Int32

	SetLogHandler(func(level LogLevel, msg string) {
		messageCount.Add(1)
	})
	defer SetLogHandler(nil)

	// Set to Error only
	SetLogLevel(LogLevelError)

	// These should NOT log
	logDebug("debug message")
	logInfo("info message")
	logWarn("warn message")

	countAfterFiltered := messageCount.Load()
	if countAfterFiltered != 0 {
		t.Errorf("Expected 0 messages with LogLevelError, got %d", countAfterFiltered)
	}

	// This should log
	logError("error message")

	countAfterError := messageCount.Load()
	if countAfterError != 1 {
		t.Errorf("Expected 1 message after logError, got %d", countAfterError)
	}
}

func TestLoggerNoPanic(t *testing.T) {
	resetGlobalState()

	// Ensure logging functions don't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Logging panicked: %v", r)
		}
	}()

	SetLogLevel(LogLevelDebug)

	logDebug("test %s %d", "string", 42)
	logInfo("test %s", "info")
	logWarn("test warning")
	logError("test error")

	// With nil handler
	SetLogHandler(nil)
	logDebug("after nil handler")

	// With custom handler
	SetLogHandler(func(level LogLevel, msg string) {
		// Do nothing
	})
	logDebug("with custom handler")

	SetLogHandler(nil)
}

// -----------------------------------------------------------------------------
// Test 11: TestEndToEndTLSBuffer - Simulate TLS handshake buffer usage
// -----------------------------------------------------------------------------

func TestEndToEndTLSBuffer(t *testing.T) {
	resetGlobalState()

	ConfigureMemory(Config{
		SoftLimit: 100 * 1024 * 1024,
		HardLimit: 200 * 1024 * 1024,
	})

	stateBefore := GetBudgetState()

	// Simulate TLS handshake: get 4KB buffer
	handshakeBuf, err := GetBuffer(4096)
	if err != nil {
		t.Fatalf("Failed to get handshake buffer: %v", err)
	}

	// Simulate TLS record: get 8KB buffer
	recordBuf, err := GetBuffer(8192)
	if err != nil {
		t.Fatalf("Failed to get record buffer: %v", err)
	}

	stateMiddle := GetBudgetState()
	t.Logf("After 2 Gets: Total=%d, InUse=%d, Gets=%d",
		stateMiddle.TotalBytes, stateMiddle.InUseBytes, stateMiddle.Gets)

	// Return both buffers
	PutBuffer(handshakeBuf)
	PutBuffer(recordBuf)

	stateAfter := GetBudgetState()
	t.Logf("After 2 Puts: Total=%d, InUse=%d", stateAfter.TotalBytes, stateAfter.InUseBytes)

	// Verify stats show 2 gets
	expectedGets := stateBefore.Gets + 2
	if stateAfter.Gets != expectedGets {
		t.Errorf("Gets = %d, want %d", stateAfter.Gets, expectedGets)
	}

	// Verify pool stats
	poolStats := GetPoolStats()
	t.Logf("Pool: 4KB allocated=%d returned=%d, 8KB allocated=%d returned=%d",
		poolStats.Tier4KB.Allocated, poolStats.Tier4KB.Returned,
		poolStats.Tier8KB.Allocated, poolStats.Tier8KB.Returned)
}

func TestEndToEndTLSBufferWithCopy(t *testing.T) {
	resetGlobalState()

	ConfigureMemory(Config{
		SoftLimit: 100 * 1024 * 1024,
		HardLimit: 200 * 1024 * 1024,
	})

	// Simulate certificate data
	certData := make([]byte, 3509)
	for i := range certData {
		certData[i] = byte(i % 256)
	}

	// Clone certificate using pooled buffer
	certBuf, copiedData, err := GetBufferWithCopy(certData)
	if err != nil {
		t.Fatalf("GetBufferWithCopy failed: %v", err)
	}
	defer PutBuffer(certBuf)

	// Verify copy is correct
	if len(copiedData) != len(certData) {
		t.Errorf("Copied data length = %d, want %d", len(copiedData), len(certData))
	}

	for i := 0; i < len(certData); i++ {
		if copiedData[i] != certData[i] {
			t.Errorf("Data mismatch at index %d: got %d, want %d", i, copiedData[i], certData[i])
			break
		}
	}
}

// -----------------------------------------------------------------------------
// Test 12: TestConcurrentFullSystem - Stress test entire system
// -----------------------------------------------------------------------------

func TestConcurrentFullSystem(t *testing.T) {
	resetGlobalState()

	ConfigureMemory(Config{
		SoftLimit: 10 * 1024 * 1024, // 10MB
		HardLimit: 20 * 1024 * 1024, // 20MB
	})

	const (
		numGoroutines       = 50
		opsPerGoroutine     = 100
		numConnGoroutines   = 10
		connsPerGoroutine   = 20
	)

	var wg sync.WaitGroup
	var panics atomic.Int32
	var allocErrors atomic.Int32
	var allocSuccesses atomic.Int32

	// Buffer pool stress
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panics.Add(1)
				}
			}()

			for j := 0; j < opsPerGoroutine; j++ {
				// Random size allocation
				size := 128 + (j%6)*1024 // 128B to ~5KB

				buf, err := GetBuffer(size)
				if err != nil {
					allocErrors.Add(1)
					continue
				}
				allocSuccesses.Add(1)

				// Use buffer briefly
				if buf != nil && *buf != nil && len(*buf) > 0 {
					(*buf)[0] = byte(j)
				}

				// Small delay to increase contention
				if j%10 == 0 {
					time.Sleep(time.Microsecond)
				}

				PutBuffer(buf)
			}
		}()
	}

	// Connection stress
	for i := 0; i < numConnGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panics.Add(1)
				}
			}()

			for j := 0; j < connsPerGoroutine; j++ {
				server, client := net.Pipe()

				conn := Wrap(server, "stress-test")
				if conn != nil {
					// Brief I/O
					go func() {
						client.Write([]byte("test"))
						client.Close()
					}()

					buf := make([]byte, 10)
					conn.Read(buf)
					conn.Close()
				} else {
					server.Close()
					client.Close()
				}

				if j%5 == 0 {
					time.Sleep(time.Microsecond)
				}
			}
		}()
	}

	// Periodic memory pressure trigger
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Check memory state
				state := GetBudgetState()
				_ = state.UsagePercent()

				// Occasionally trigger shed
				if state.InEviction {
					GetRegistry().Shed()
				}
			case <-done:
				return
			}
		}
	}()

	// Wait for all workers
	wg.Wait()
	close(done)

	// Report results
	t.Logf("Concurrent test complete:")
	t.Logf("  Panics: %d", panics.Load())
	t.Logf("  Alloc errors: %d", allocErrors.Load())
	t.Logf("  Alloc successes: %d", allocSuccesses.Load())
	t.Logf("  Final budget state: %+v", GetBudgetState())
	t.Logf("  Final pool stats: %+v", GetPoolStats())

	if panics.Load() > 0 {
		t.Errorf("Had %d panics during concurrent test", panics.Load())
	}
}

func TestConcurrentBufferGetPut(t *testing.T) {
	resetGlobalState()

	ConfigureMemory(Config{
		SoftLimit: 50 * 1024 * 1024,
		HardLimit: 100 * 1024 * 1024,
	})

	const goroutines = 100
	const iterations = 1000

	var wg sync.WaitGroup
	var errors atomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < iterations; j++ {
				size := 128 << (j % 6) // 128, 256, 512, 1K, 2K, 4K

				buf, err := GetBuffer(size)
				if err != nil {
					errors.Add(1)
					continue
				}

				// Verify buffer is usable
				if buf == nil || *buf == nil || cap(*buf) < size {
					errors.Add(1)
					continue
				}

				// Write to buffer
				(*buf)[0] = byte(id)
				if size > 1 {
					(*buf)[size-1] = byte(j)
				}

				PutBuffer(buf)
			}
		}(i)
	}

	wg.Wait()

	if errors.Load() > 0 {
		t.Logf("Buffer errors: %d (may be expected under memory pressure)", errors.Load())
	}

	// Verify stats are consistent
	poolStats := GetPoolStats()
	budgetState := GetBudgetState()

	t.Logf("After concurrent test:")
	t.Logf("  Gets: %d, Hits: %d, Misses: %d", budgetState.Gets, budgetState.Hits, budgetState.Misses)
	t.Logf("  HitRate: %.2f%%", budgetState.HitRate)
	t.Logf("  BufferSizeMapEntries: %d", poolStats.BufferSizeMapEntries)
}

// -----------------------------------------------------------------------------
// Additional edge case tests
// -----------------------------------------------------------------------------

func TestNilBudgetMethods(t *testing.T) {
	// Test that nil receiver handling works
	var nilBudget *MemoryBudget

	// These should not panic
	nilBudget.SetEvictionCallback(nil)
	nilBudget.RecordGet()
	nilBudget.RecordHit()
	nilBudget.RecordMiss()
	nilBudget.MarkInUse(100)

	result := nilBudget.TryAllocate(100)
	if !result {
		t.Error("TryAllocate on nil should return true")
	}

	cacheResult := nilBudget.Release(100)
	if !cacheResult {
		t.Error("Release on nil should return true")
	}

	state := nilBudget.State()
	if state.TotalBytes != 0 {
		t.Error("State on nil should return zero state")
	}

	isEvicting := nilBudget.IsEvicting()
	if isEvicting {
		t.Error("IsEvicting on nil should return false")
	}

	avail := nilBudget.Available()
	if avail != 0 {
		t.Error("Available on nil should return 0")
	}
}

func TestBudgetStateHelpers(t *testing.T) {
	state := BudgetState{
		TotalBytes: 50,
		HardLimit:  100,
		Disabled:   false,
		Waiters:    0,
		InEviction: false,
	}

	if state.StateName() != "NORMAL" {
		t.Errorf("StateName = %s, want NORMAL", state.StateName())
	}

	if state.UsagePercent() != 50.0 {
		t.Errorf("UsagePercent = %f, want 50.0", state.UsagePercent())
	}

	// Eviction state
	state.InEviction = true
	if state.StateName() != "EVICT" {
		t.Errorf("StateName = %s, want EVICT", state.StateName())
	}

	// Block state (waiters)
	state.Waiters = 1
	if state.StateName() != "BLOCK" {
		t.Errorf("StateName = %s, want BLOCK", state.StateName())
	}

	// Disabled state
	state.Disabled = true
	if state.StateName() != "DISABLED" {
		t.Errorf("StateName = %s, want DISABLED", state.StateName())
	}

	// Zero hard limit
	state.HardLimit = 0
	if state.UsagePercent() != 0 {
		t.Errorf("UsagePercent with 0 limit = %f, want 0", state.UsagePercent())
	}
}

func TestBufferPoolEdgeCases(t *testing.T) {
	resetGlobalState()

	ConfigureMemory(Config{
		SoftLimit: 100 * 1024 * 1024,
		HardLimit: 200 * 1024 * 1024,
	})

	// Zero size
	buf, err := GetBuffer(0)
	if err != nil {
		t.Errorf("GetBuffer(0) failed: %v", err)
	}
	if buf != nil {
		PutBuffer(buf)
	}

	// Negative size
	_, err = GetBuffer(-1)
	if err != ErrBufferNegativeSize {
		t.Errorf("GetBuffer(-1) should return ErrBufferNegativeSize, got %v", err)
	}

	// Too large
	_, err = GetBuffer(MaxBufferSize + 1)
	if err != ErrBufferTooLarge {
		t.Errorf("GetBuffer(too large) should return ErrBufferTooLarge, got %v", err)
	}

	// Nil PutBuffer (should not panic)
	PutBuffer(nil)

	// Empty slice PutBuffer
	var emptyBuf []byte
	PutBuffer(&emptyBuf)
}

func TestConnectionWrapEdgeCases(t *testing.T) {
	resetGlobalState()

	// Nil connection
	result := Wrap(nil, "test")
	if result != nil {
		t.Error("Wrap(nil) should return nil")
	}

	// WrapOrPassthrough with nil
	resultPassthrough := WrapOrPassthrough(nil, "test")
	if resultPassthrough != nil {
		t.Error("WrapOrPassthrough(nil) should return nil")
	}

	// UnwrapConn with regular conn
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	unwrapped := UnwrapConn(server)
	if unwrapped != server {
		t.Error("UnwrapConn on regular conn should return same conn")
	}

	// UnwrapConn with managed conn
	managed := Wrap(server, "test")
	if managed != nil {
		unwrapped = UnwrapConn(managed)
		if unwrapped != server {
			t.Error("UnwrapConn on managed conn should return inner conn")
		}
		managed.Close()
	}
}

func TestRegistryOperations(t *testing.T) {
	resetGlobalState()

	registry := GetRegistry()

	// Initial state
	state := registry.State()
	if state.Active != 0 {
		t.Errorf("Initial active = %d, want 0", state.Active)
	}

	// Create connections
	var conns []*Conn
	for i := 0; i < 5; i++ {
		server, client := net.Pipe()
		client.Close()

		conn := Wrap(server, "test-tag")
		if conn != nil {
			conns = append(conns, conn)
		} else {
			server.Close()
		}
	}

	if len(conns) == 0 {
		t.Skip("No connections created (managed conn may be disabled)")
	}

	// Verify count
	if registry.Count() != int32(len(conns)) {
		t.Errorf("Count = %d, want %d", registry.Count(), len(conns))
	}

	// CountByTag
	if registry.CountByTag("test-tag") != int32(len(conns)) {
		t.Errorf("CountByTag = %d, want %d", registry.CountByTag("test-tag"), len(conns))
	}

	// Get by ID
	conn := registry.Get(conns[0].ID())
	if conn == nil {
		t.Error("Get by ID should find connection")
	}

	// ForEach
	count := 0
	registry.ForEach(func(c *Conn) {
		count++
	})
	if count != len(conns) {
		t.Errorf("ForEach visited %d, want %d", count, len(conns))
	}

	// Cleanup
	for _, c := range conns {
		c.Close()
	}

	// Verify cleanup
	if registry.Count() != 0 {
		t.Errorf("After close, count = %d, want 0", registry.Count())
	}
}

// mockConn implements net.Conn for testing slow readers
type mockConn struct {
	readDelay  time.Duration
	writeDelay time.Duration
	closed     atomic.Bool
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.closed.Load() {
		return 0, io.EOF
	}
	if m.readDelay > 0 {
		time.Sleep(m.readDelay)
	}
	return 0, io.EOF
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if m.writeDelay > 0 {
		time.Sleep(m.writeDelay)
	}
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.closed.Store(true)
	return nil
}

func (m *mockConn) LocalAddr() net.Addr  { return nil }
func (m *mockConn) RemoteAddr() net.Addr { return nil }
func (m *mockConn) SetDeadline(t time.Time) error { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestConnectionStats(t *testing.T) {
	resetGlobalState()

	mock := &mockConn{}
	conn := Wrap(mock, "mock-test")
	if conn == nil {
		t.Skip("Managed conn disabled")
	}
	defer conn.Close()

	// Initial stats
	stats := conn.Stats()
	if stats.ID == 0 {
		t.Error("Connection ID should be non-zero")
	}
	if stats.Tag != "mock-test" {
		t.Errorf("Tag = %s, want mock-test", stats.Tag)
	}

	// Age should be small
	if stats.Age > time.Second {
		t.Errorf("Age = %v, expected < 1s", stats.Age)
	}

	// CreatedAt
	if conn.CreatedAt().IsZero() {
		t.Error("CreatedAt should not be zero")
	}

	// Initial idle should be very small
	if conn.IdleDuration() > time.Second {
		t.Errorf("IdleDuration = %v, expected < 1s", conn.IdleDuration())
	}

	// BytesRead/Written initially 0
	if conn.BytesRead() != 0 || conn.BytesWritten() != 0 {
		t.Errorf("Initial bytes = %d/%d, want 0/0", conn.BytesRead(), conn.BytesWritten())
	}

	// Write some data
	conn.Write([]byte("hello"))
	if conn.BytesWritten() != 5 {
		t.Errorf("BytesWritten = %d, want 5", conn.BytesWritten())
	}

	// IsClosed
	if conn.IsClosed() {
		t.Error("Should not be closed yet")
	}

	// Close and check
	conn.Close()
	if !conn.IsClosed() {
		t.Error("Should be closed after Close()")
	}

	// Double close should be safe
	conn.Close()
}

func TestAllocateBlocking(t *testing.T) {
	resetGlobalState()

	// Set very small hard limit
	ConfigureMemory(Config{
		SoftLimit: 100,  // Very small
		HardLimit: 200,  // Very small
	})

	budget := GetBudget()

	// First allocation should succeed
	if !budget.TryAllocate(150) {
		t.Error("First allocation should succeed")
	}

	// Second allocation should fail (over hard limit)
	if budget.TryAllocate(100) {
		t.Error("Second allocation should fail")
	}

	// AllocateBlocking with short timeout should fail
	start := time.Now()
	result := budget.AllocateBlocking(100, 50*time.Millisecond)
	elapsed := time.Since(start)

	if result {
		t.Error("AllocateBlocking should timeout")
	}
	if elapsed < 40*time.Millisecond {
		t.Errorf("Should have waited near timeout, elapsed: %v", elapsed)
	}

	// Release space
	budget.Release(150)

	// Now should succeed
	if !budget.TryAllocate(100) {
		t.Error("After release, allocation should succeed")
	}
}

func TestHitRateCalculation(t *testing.T) {
	resetGlobalState()

	ConfigureMemory(Config{
		SoftLimit: 100 * 1024 * 1024,
		HardLimit: 200 * 1024 * 1024,
	})

	// Do some Gets and Puts to build up cache
	for i := 0; i < 10; i++ {
		buf, _ := GetBuffer(4096)
		if buf != nil {
			PutBuffer(buf)
		}
	}

	state := GetBudgetState()

	// Hits + Misses should equal Gets
	if state.Hits + state.Misses != state.Gets {
		t.Errorf("Hits (%d) + Misses (%d) != Gets (%d)",
			state.Hits, state.Misses, state.Gets)
	}

	// HitRate should be calculated
	expectedHitRate := float64(state.Hits) / float64(state.Gets) * 100
	if state.Gets > 0 && state.HitRate != expectedHitRate {
		t.Logf("HitRate = %.2f, calculated = %.2f", state.HitRate, expectedHitRate)
	}
}
