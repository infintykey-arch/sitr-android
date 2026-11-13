package com.sitr.vault;

import android.content.Context;
import android.content.SharedPreferences;

final class VaultAttemptLimiter {
    private static final String PREFERENCES = "sitr_vault_attempt_limits_v1";
    private static final long BASE_DELAY_MILLIS = 30_000L;
    private static final long MAX_DELAY_MILLIS = 15L * 60L * 1000L;

    private VaultAttemptLimiter() {}

    static long delayForFailureCount(int failures) {
        if (failures < 3) return 0L;
        int exponent = Math.min(5, failures - 3);
        return Math.min(MAX_DELAY_MILLIS, BASE_DELAY_MILLIS << exponent);
    }

    static long remainingMillis(Context context, String vaultId) {
        SharedPreferences preferences = preferences(context);
        String key = key(vaultId);
        long until = preferences.getLong(key + ".until", 0L);
        long remaining = until - System.currentTimeMillis();
        if (remaining <= 0L) return 0L;
        return Math.min(MAX_DELAY_MILLIS, remaining);
    }

    static long recordFailure(Context context, String vaultId) {
        SharedPreferences preferences = preferences(context);
        String key = key(vaultId);
        int failures = Math.min(1000, preferences.getInt(key + ".count", 0) + 1);
        long delay = delayForFailureCount(failures);
        long until = delay == 0L ? 0L : System.currentTimeMillis() + delay;
        boolean saved = preferences.edit()
                .putInt(key + ".count", failures)
                .putLong(key + ".until", until)
                .commit();
        if (!saved && delay > 0L) return delay;
        return delay;
    }

    static void recordSuccess(Context context, String vaultId) {
        preferences(context).edit().remove(key(vaultId) + ".count")
                .remove(key(vaultId) + ".until").commit();
    }

    private static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE);
    }

    private static String key(String vaultId) {
        if (vaultId == null || vaultId.trim().isEmpty()) return "unknown-vault";
        return vaultId.replaceAll("[^A-Za-z0-9_-]", "_");
    }
}
