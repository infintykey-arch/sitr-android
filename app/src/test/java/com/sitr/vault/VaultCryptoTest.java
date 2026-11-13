package com.sitr.vault;

import org.junit.Test;

import java.util.Arrays;

import javax.crypto.AEADBadTagException;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;

public class VaultCryptoTest {
    @Test public void encryptedPayloadRoundTripsWithItsVaultKey() throws Exception {
        byte[] salt = new byte[32];
        Arrays.fill(salt, (byte) 0x41);
        byte[] rawKey = VaultCrypto.derive("correct horse battery staple".toCharArray(), salt);
        SecretKeySpec key = new SecretKeySpec(rawKey, "AES");
        Arrays.fill(rawKey, (byte) 0);
        byte[] original = "local project API token".getBytes("UTF-8");

        byte[] encrypted = VaultCrypto.encryptPayload("project-vault-alpha", key, original);
        byte[] decrypted = VaultCrypto.decryptPayload("project-vault-alpha", key, encrypted);

        assertArrayEquals(original, decrypted);
        assertFalse(Arrays.equals(original, encrypted));
        Arrays.fill(encrypted, (byte) 0);
        Arrays.fill(decrypted, (byte) 0);
    }

    @Test(expected = AEADBadTagException.class)
    public void encryptedPayloadCannotBeMovedToAnotherVault() throws Exception {
        byte[] salt = new byte[32];
        Arrays.fill(salt, (byte) 0x22);
        byte[] rawKey = VaultCrypto.derive("another strong test password".toCharArray(), salt);
        SecretKeySpec key = new SecretKeySpec(rawKey, "AES");
        Arrays.fill(rawKey, (byte) 0);
        byte[] encrypted = VaultCrypto.encryptPayload("vault-one", key, "private".getBytes("UTF-8"));

        VaultCrypto.decryptPayload("vault-two", key, encrypted);
    }

    @Test(expected = IllegalArgumentException.class)
    public void newVaultRejectsPasswordShorterThanEightCharacters() throws Exception {
        VaultCrypto.create("test-vault", "1234567".toCharArray());
    }
}
