/*
 * Probe the KeyStore alias and Cipher that
 * com.google.android.apps.authenticator2 actually uses.
 * The script waits for the app to encrypt or decrypt, then logs those calls.
 * It reads no database and hard-codes no alias.
 *
 * Usage
 *   frida -U -f com.google.android.apps.authenticator2 -l probe_keystore_alias.js
 *
 *   Spawn the app. The Frida 17 CLI ships with the Java bridge, and this
 *   file has no Java import.
 *   Java.performNow installs the hooks before the main thread resumes, so
 *   the startup decrypt pass goes through these hooks.
 *   Results go out through console.log and show up as lines in the frida
 *   window.
 *
 *   With -H, official frida-server 17.24.3 fails before the script runs:
 *
 *     Failed to load script: the connection is closed
 *
 *   The Java bridge is about 237 KB, above libsoup's default WebSocket limit
 *   of 131072 bytes, so the server closes the connection. On the phone, use
 *   /data/local/tmp/frida-server (17.24.3 with max-total-message-size raised
 *   to 8 MiB). USB -U accepts the full bridge.
 *
 * How it works
 *   The alias is recorded from the app's own KeyStore calls. The script does
 *   not assume the name is "Authenticator":
 *     getKey(String, char[]), containsAlias(String),
 *     getEntry(String, ProtectionParameter)
 *   Plaintext comes from Cipher. On init, System.identityHashCode keys the
 *   mode, algorithm, and key alias for that Cipher instance. When the
 *   parameters expose getIV(), the IV is stored too. GCMParameterSpec is one
 *   such parameter.
 *   doFinal matches the same Cipher to that init. In DECRYPT mode the log
 *   also includes the UTF-8 plaintext.
 *   Only the overloads the app actually reaches are hooked:
 *     init(int, Key)
 *     init(int, Key, AlgorithmParameterSpec)
 *     init(int, Key, AlgorithmParameters)
 *     doFinal(byte[])
 *     doFinal(byte[], int, int)
 *   A row the UI has not read stays absent. A deleted row stays absent unless
 *   this query touches it.
 *
 * Output
 *   [KeyStore.getKey] alias="..."          blank line before each record
 *   [Cipher.init] mode=DECRYPT algo=AES iv=... key=...
 *   [Cipher.doFinal] mode=DECRYPT iv=...
 *   in=...
 *   b64=...
 *   out=...
 *   PLAINTEXT="..."
 *   PLAINTEXT is the decrypted plaintext, decoded as UTF-8. in and out are
 *   hexadecimal.
 *   in is the slice doFinal actually consumes. 7.2 AES decryption passes the
 *   whole array with offset 12, so in starts after the leading IV.
 *   b64 is the whole byte[] as standard Base64 with no inserted newlines.
 *   otp_table.secret is that same text laid out with Base64.DEFAULT, which
 *   adds newlines: one every 76 characters, plus one trailing newline.
 *   After those newlines are removed from the secret column, it matches b64
 *   character for character.
 */

'use strict';

function hexRange(b, offset, len) {
    if (b === null || b === undefined) return '(null)';
    if (offset === undefined) {
        offset = 0;
        len = b.length;
    }
    var out = [];
    for (var i = 0; i < len; i++) {
        var x = b[offset + i];
        if (x < 0) x += 256;
        out.push(('0' + (x & 0xff).toString(16)).slice(-2));
    }
    return out.join('');
}
function utf8(b) {
    if (b === null || b === undefined) return '(null)';
    try { return String(Java.use('java.lang.String').$new(b, 'UTF-8')); } catch (e) { return '(non-utf8)'; }
}
function keyDesc(key) {
    if (key === null || key === undefined) return '(null)';
    var names = [
        'android.security.keystore2.AndroidKeyStoreKey',
        'android.security.keystore.AndroidKeyStoreKey'
    ];
    for (var i = 0; i < names.length; i++) {
        try {
            return String(Java.cast(key, Java.use(names[i])).getAlias());
        } catch (e) {}
    }
    try {
        return String(Java.use('java.lang.String').valueOf(key));
    } catch (e2) {
        return '(unknown)';
    }
}

var OP = { 1: 'ENCRYPT', 2: 'DECRYPT', 3: 'WRAP', 4: 'UNWRAP' };
var state = {};
function id(o) { return Java.use('java.lang.System').identityHashCode(o); }

function install() {
    console.log('=== alias+decrypt hooks installed ===');

    var KeyStore = Java.use('java.security.KeyStore');

    KeyStore.getKey.overload('java.lang.String', '[C').implementation = function (alias, pwd) {
        console.log('\n[KeyStore.getKey] alias="' + alias + '"');
        return this.getKey(alias, pwd);
    };
    KeyStore.containsAlias.implementation = function (alias) {
        var r = this.containsAlias(alias);
        console.log('[KeyStore.containsAlias] alias="' + alias + '" -> ' + r);
        return r;
    };
    try {
        KeyStore.getEntry.overload('java.lang.String', 'java.security.KeyStore$ProtectionParameter').implementation = function (alias, p) {
            console.log('[KeyStore.getEntry] alias="' + alias + '"');
            return this.getEntry(alias, p);
        };
    } catch (e) {}

    var Cipher = Java.use('javax.crypto.Cipher');
    var GCM = Java.use('javax.crypto.spec.GCMParameterSpec');
    var Base64 = Java.use('android.util.Base64');

    function b64db(bytes) {
        if (bytes === null || bytes === undefined) return '(null)';
        // NO_WRAP = 2. Same alphabet as DEFAULT, with no inserted newlines.
        return String(Base64.encodeToString(bytes, 2));
    }

    function readIv(params) {
        if (params === null || params === undefined) return null;
        try {
            var iv = GCM.getIV.call(params);
            if (iv !== null) return hexRange(iv);
        } catch (e) {}
        try {
            var iv2 = params.getIV();
            if (iv2 !== null) return hexRange(iv2);
        } catch (e2) {}
        return null;
    }

    function rec(self, opmode, key, params) {
        var info = { mode: OP[opmode] || opmode, iv: readIv(params), algo: '' };
        try { info.algo = String(key.getAlgorithm()); } catch (e) {}
        state[id(self)] = info;
        console.log('[Cipher.init] mode=' + info.mode + ' algo=' + info.algo +
             ' iv=' + info.iv + ' key=' + keyDesc(key));
    }

    Cipher.init.overload('int', 'java.security.Key').implementation = function (o, k) { rec(this, o, k, null); return this.init(o, k); };
    Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (o, k, p) { rec(this, o, k, p); return this.init(o, k, p); };
    Cipher.init.overload('int', 'java.security.Key', 'java.security.AlgorithmParameters').implementation = function (o, k, p) { rec(this, o, k, p); return this.init(o, k, p); };

    function fin(self, input, result, offset, len) {
        var info = state[id(self)] || { mode: '?', iv: null };
        if (info.iv === null && typeof offset === 'number' && offset > 0) {
            info.iv = hexRange(input, 0, offset);
        }
        console.log('[Cipher.doFinal] mode=' + info.mode + ' iv=' + info.iv);
        console.log('in=' + hexRange(input, offset, len));
        console.log('b64=' + b64db(input));
        console.log('out=' + hexRange(result));
        if (info.mode === 'DECRYPT') console.log('PLAINTEXT="' + utf8(result) + '"');
    }
    Cipher.doFinal.overload('[B').implementation = function (i) {
        var r = this.doFinal(i);
        try { fin(this, i, r, 0, i.length); } catch (e) {}
        return r;
    };
    Cipher.doFinal.overload('[B', 'int', 'int').implementation = function (i, a, b) {
        var r = this.doFinal(i, a, b);
        try { fin(this, i, r, a, b); } catch (e) {}
        return r;
    };

    console.log('=== ready. Open the app / view an account to trigger DECRYPT ===');
}

try {
    Java.performNow(install);
} catch (e) {
    console.log('[!] performNow failed, waiting for the VM: ' + e);
    Java.perform(install);
}
