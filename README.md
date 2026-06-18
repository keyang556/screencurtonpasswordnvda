# Screen Curtain Password for NVDA

This NVDA add-on adds password protection around Screen Curtain privacy actions.

It can:

- Require a password before Screen Curtain is disabled.
- Require a password before NVDA exits or restarts while Screen Curtain is active.
- Store only a salted PBKDF2-HMAC-SHA256 password hash, not the plain password.
- Keep password fields hidden by default, with a Show password checkbox beside them.
- Reset a forgotten password by entering `00000` at the password prompt and waiting five minutes.

Settings are available from NVDA menu, Preferences, Settings, Screen Curtain Password.

The add-on is inspired by nvaccess/nvda issue #20335.
