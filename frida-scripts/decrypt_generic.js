/*
 * Generic hook for com.google.android.apps.authenticator2.
 * When the app decrypts a row, record the entry id and the decrypted plaintext.
 *
 *   frida -U -f com.google.android.apps.authenticator2 -l decrypt_generic.js
 *
 * Spawn the app. Attaching to a process that is already open misses the
 * startup load, which has already finished.
 * The Frida 17 CLI ships with the Java bridge. Java.performNow installs the
 * hooks before the main thread resumes.
 *
 * With -H, official frida-server 17.24.3 fails before the script runs. The
 * client only sees:
 *
 *   Failed to load script: the connection is closed
 *
 * libsoup fixes the WebSocket max-total-message-size at 131072 bytes
 * (128 KiB). Loading the Java bridge from the CLI sends about 237 KB of
 * java.js in one message. Past that limit the server closes the connection.
 * The server process stays up, and --help has no option to raise the limit.
 * Measured: a script body of 130911 bytes loads; 130912 bytes drops the
 * connection. USB -U uses another transport and accepts the full bridge.
 *
 * Workaround: run a locally built 17.24.3 frida-server on the phone at
 * /data/local/tmp/frida-server. That build only raises
 * max-total-message-size to 8 MiB (the
 * soup_websocket_connection_set_max_total_message_size call in socket.vala).
 * Leave max_incoming_payload_size as it is. That value also sets the outgoing
 * fragment size, and a larger value no longer matches the official 17.24.3
 * client.
 *
 * The plaintext and the id come from different calls, back to back on the
 * same thread, so the script keeps two hooks:
 *   start  Cursor.getString hits the secret column and reads unique_id and
 *          ordering from that same cursor
 *   end    the return value of Cipher.doFinal(byte[], int, int) is the
 *          plaintext
 * On Android M and above, 7.2 finishes decryption with this one doFinal
 * overload. Older RSA goes through CipherInputStream and stays outside this
 * script.
 *
 * Output
 *   [+] ordering=1 unique_id=... secret=...
 *   secret is the decrypted plaintext.
 */

'use strict';

var pending = {};
var seen = {};

function tid() {
    return Process.getCurrentThreadId();
}

function install() {
    var Windowed = Java.use('android.database.AbstractWindowedCursor');
    Windowed.getString.overload('int').implementation = function (index) {
        var value = this.getString(index);
        try {
            if (value !== null && index === this.getColumnIndex('secret')) {
                var idIdx = this.getColumnIndex('unique_id');
                var ordIdx = this.getColumnIndex('ordering');
                var uniqueId = idIdx < 0 ? null : this.getString(idIdx);
                var ordering = ordIdx < 0 ? null : this.getInt(ordIdx);
                pending[tid()] = {
                    uniqueId: uniqueId === null ? null : String(uniqueId),
                    ordering: ordering === null ? null : String(ordering)
                };
            }
        } catch (e) {}
        return value;
    };

    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B', 'int', 'int').implementation = function (input, offset, len) {
        var result = this.doFinal(input, offset, len);
        try {
            var id = tid();
            var row = pending[id];
            if (row !== undefined) {
                delete pending[id];
                var key = row.uniqueId !== null ? row.uniqueId : row.ordering;
                if (key === null || !seen[key]) {
                    if (key !== null) {
                        seen[key] = true;
                    }
                    var plain = String(Java.use('java.lang.String').$new(result, 'UTF-8'));
                    console.log('[+] ordering=' + (row.ordering === null ? '' : row.ordering) +
                                ' unique_id=' + (row.uniqueId === null ? '' : row.uniqueId) +
                                ' secret=' + plain);
                }
            }
        } catch (e) {}
        return result;
    };

    console.log('[*] hooks installed');
}

try {
    Java.performNow(install);
} catch (e) {
    console.log('[!] performNow failed, waiting for the VM: ' + e);
    Java.perform(install);
}
