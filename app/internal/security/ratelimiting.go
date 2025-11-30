// Package security provides rate limiting functionality.
// Implements SR-003 (Brute Force Protection) and SR-015 (Rate Limiting).
package security

import (
	"sync"
	"time"
)

// RateLimiter implements token bucket algorithm for rate limiting.
// Thread-safe implementation using mutex for concurrent access.
type RateLimiter struct {
	// Map of identifier (IP or user ID) to rate limit state
	limiters map[string]*bucketState
	mu       sync.RWMutex

	// Configuration
	maxTokens  int           // Maximum tokens in bucket
	refillRate time.Duration // Time between token refills

	// Cleanup ticker to remove old entries
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
}

// bucketState tracks the token bucket state for a single identifier.
type bucketState struct {
	tokens     int       // Current number of tokens
	lastRefill time.Time // Last time tokens were refilled
	mu         sync.Mutex
}

// NewRateLimiter creates a new rate limiter with specified configuration.
//
// Parameters:
//   - maxTokens: Maximum number of tokens (requests) allowed in the bucket
//   - refillRate: How often to add a token back to the bucket
//
// Example:
//
//	// Allow 5 requests per minute
//	limiter := NewRateLimiter(5, 12*time.Second) // 60s / 5 requests = 12s per token
func NewRateLimiter(maxTokens int, refillRate time.Duration) *RateLimiter {
	rl := &RateLimiter{
		limiters:    make(map[string]*bucketState),
		maxTokens:   maxTokens,
		refillRate:  refillRate,
		stopCleanup: make(chan struct{}),
	}

	// Start background cleanup to remove old entries
	rl.cleanupTicker = time.NewTicker(10 * time.Minute)
	go rl.cleanup()

	return rl
}

// Allow checks if a request from the given identifier should be allowed.
// Returns true if request is allowed, false if rate limit exceeded.
//
// Parameters:
//   - identifier: Unique identifier for rate limiting (IP address or user ID)
//
// Returns:
//   - bool: true if request allowed, false if rate limited
func (rl *RateLimiter) Allow(identifier string) bool {
	rl.mu.Lock()
	bucket, exists := rl.limiters[identifier]
	if !exists {
		// First request from this identifier - create new bucket
		bucket = &bucketState{
			tokens:     rl.maxTokens - 1, // Consume one token for this request
			lastRefill: time.Now(),
		}
		rl.limiters[identifier] = bucket
		rl.mu.Unlock()
		return true
	}
	rl.mu.Unlock()

	// Refill tokens based on time elapsed
	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	elapsed := time.Since(bucket.lastRefill)
	tokensToAdd := int(elapsed / rl.refillRate)

	if tokensToAdd > 0 {
		bucket.tokens += tokensToAdd
		if bucket.tokens > rl.maxTokens {
			bucket.tokens = rl.maxTokens
		}
		bucket.lastRefill = time.Now()
	}

	// Check if we have tokens available
	if bucket.tokens > 0 {
		bucket.tokens--
		return true
	}

	// Rate limit exceeded
	return false
}

// Reset removes the rate limit state for a given identifier.
// Useful for clearing lockouts or resetting limits.
func (rl *RateLimiter) Reset(identifier string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.limiters, identifier)
}

// cleanup periodically removes old, inactive entries to prevent memory leaks.
func (rl *RateLimiter) cleanup() {
	for {
		select {
		case <-rl.cleanupTicker.C:
			rl.mu.Lock()
			now := time.Now()
			for id, bucket := range rl.limiters {
				bucket.mu.Lock()
				// Remove entries inactive for more than 1 hour
				if now.Sub(bucket.lastRefill) > time.Hour {
					delete(rl.limiters, id)
				}
				bucket.mu.Unlock()
			}
			rl.mu.Unlock()
		case <-rl.stopCleanup:
			return
		}
	}
}

// Stop stops the cleanup goroutine and releases resources.
func (rl *RateLimiter) Stop() {
	rl.cleanupTicker.Stop()
	close(rl.stopCleanup)
}

// AccountLockout tracks failed login attempts and implements account lockout.
// Implements SR-003: Brute Force Protection.
type AccountLockout struct {
	// Map of account identifier to lockout state
	lockouts map[string]*lockoutState
	mu       sync.RWMutex

	// Configuration
	threshold int           // Failed attempts before lockout
	duration  time.Duration // How long account stays locked
}

// lockoutState tracks failed attempts and lockout status for an account.
type lockoutState struct {
	failedAttempts int
	lockedUntil    time.Time
	lastAttempt    time.Time
	mu             sync.Mutex
}

// NewAccountLockout creates a new account lockout tracker.
//
// Parameters:
//   - threshold: Number of failed attempts before lockout
//   - duration: How long the account stays locked
//
// Example:
//
//	// Lock account for 30 minutes after 10 failed attempts
//	lockout := NewAccountLockout(10, 30*time.Minute)
func NewAccountLockout(threshold int, duration time.Duration) *AccountLockout {
	return &AccountLockout{
		lockouts:  make(map[string]*lockoutState),
		threshold: threshold,
		duration:  duration,
	}
}

// RecordFailedAttempt records a failed login attempt.
// Returns true if account should be locked.
func (al *AccountLockout) RecordFailedAttempt(identifier string) bool {
	al.mu.Lock()
	state, exists := al.lockouts[identifier]
	if !exists {
		state = &lockoutState{
			failedAttempts: 1,
			lastAttempt:    time.Now(),
		}
		al.lockouts[identifier] = state
		al.mu.Unlock()
		return false
	}
	al.mu.Unlock()

	state.mu.Lock()
	defer state.mu.Unlock()

	// Check if enough time has passed to reset counter (30 minutes)
	if time.Since(state.lastAttempt) > 30*time.Minute {
		state.failedAttempts = 1
		state.lastAttempt = time.Now()
		return false
	}

	state.failedAttempts++
	state.lastAttempt = time.Now()

	// Check if we've exceeded threshold
	if state.failedAttempts >= al.threshold {
		state.lockedUntil = time.Now().Add(al.duration)
		return true
	}

	return false
}

// IsLocked checks if an account is currently locked.
// Returns true if locked, false if not locked or lockout expired.
func (al *AccountLockout) IsLocked(identifier string) bool {
	al.mu.RLock()
	state, exists := al.lockouts[identifier]
	al.mu.RUnlock()

	if !exists {
		return false
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	// Check if lockout has expired
	if time.Now().After(state.lockedUntil) {
		// Lockout expired, reset state
		state.failedAttempts = 0
		state.lockedUntil = time.Time{}
		return false
	}

	return !state.lockedUntil.IsZero()
}

// ResetAttempts resets failed attempt counter for an identifier.
// Call this on successful login.
func (al *AccountLockout) ResetAttempts(identifier string) {
	al.mu.Lock()
	defer al.mu.Unlock()
	delete(al.lockouts, identifier)
}

// GetLockoutTimeRemaining returns how much time is left on the lockout.
// Returns 0 if not locked.
func (al *AccountLockout) GetLockoutTimeRemaining(identifier string) time.Duration {
	al.mu.RLock()
	state, exists := al.lockouts[identifier]
	al.mu.RUnlock()

	if !exists {
		return 0
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	if state.lockedUntil.IsZero() {
		return 0
	}

	remaining := time.Until(state.lockedUntil)
	if remaining < 0 {
		return 0
	}

	return remaining
}
