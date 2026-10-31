# Frida scripts

Hooks for `com.google.android.apps.authenticator2`. Spawn with `-f` so the hooks catch the startup decrypt. The console prints OTP secrets in clear text.

Frida 17 CLI. USB works with the official server. `-H` needs the locally built 17.24.3 server at `/data/local/tmp/frida-server` (`max-total-message-size` raised to 8 MiB). The official 17.24.3 server closes the connection before the script runs.

`192.168.1.10:27042` below is the phone's frida-server address.

## decrypt_generic.js

One line per decrypted row: `ordering`, `unique_id`, and the plaintext secret. Authenticator 7.2 on Android M and above.

```powershell
frida -U -f com.google.android.apps.authenticator2 -l .\frida-scripts\decrypt_generic.js
frida -H 192.168.1.10:27042 -f com.google.android.apps.authenticator2 -l .\frida-scripts\decrypt_generic.js
```

```text
[*] hooks installed
[+] ordering=1 unique_id=... secret=...
```

## probe_keystore_alias.js

Logs the KeyStore alias the app uses, plus Cipher mode, algorithm, IV, ciphertext, Base64, and UTF-8 plaintext.

```powershell
frida -U -f com.google.android.apps.authenticator2 -l .\frida-scripts\probe_keystore_alias.js
frida -H 192.168.1.10:27042 -f com.google.android.apps.authenticator2 -l .\frida-scripts\probe_keystore_alias.js
```

```text
[KeyStore.getKey] alias="..."
[Cipher.init] mode=DECRYPT algo=AES iv=... key=...
[Cipher.doFinal] mode=DECRYPT iv=...
in=...
b64=...
out=...
PLAINTEXT="..."
```

`b64` has no line breaks. `otp_table.secret` is the same text with `Base64.DEFAULT` newlines: one every 76 characters, plus one at the end.
