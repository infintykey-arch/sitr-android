package com.sitr.vault;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class VaultAttemptLimiterTest {
    @Test public void firstTwoFailuresHaveNoDelay() {
        assertEquals(0L, VaultAttemptLimiter.delayForFailureCount(0));
        assertEquals(0L, VaultAttemptLimiter.delayForFailureCount(1));
        assertEquals(0L, VaultAttemptLimiter.delayForFailureCount(2));
    }

    @Test public void delayDoublesAfterThirdFailure() {
        assertEquals(30_000L, VaultAttemptLimiter.delayForFailureCount(3));
        assertEquals(60_000L, VaultAttemptLimiter.delayForFailureCount(4));
        assertEquals(120_000L, VaultAttemptLimiter.delayForFailureCount(5));
    }

    @Test public void delayNeverExceedsFifteenMinutes() {
        assertEquals(15L * 60L * 1000L, VaultAttemptLimiter.delayForFailureCount(8));
        assertEquals(15L * 60L * 1000L, VaultAttemptLimiter.delayForFailureCount(1000));
    }
}
