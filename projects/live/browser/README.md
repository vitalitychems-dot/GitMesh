# Disposable admin rotation browser checks

These tests run the real first-party UI and authentication routes against a new,
random development-only PostgreSQL schema for each scenario. They generate a
test-only initial key in memory, listen only on loopback, and drop their schemas
when the scenarios finish. They never initialize or reset the real administrator.

Use only a development `DATABASE_URL` already supplied by the environment.
Production runtimes are refused. Explicitly opt in:

```sh
GITMESH_BROWSER_TESTS=development npm run test:browser
```

The host needs the browsers and native libraries required by the pinned
Playwright version. The two projects use Pixel/Chromium and iPhone/WebKit phone
emulation. To run one project, append `-- --project=mobile-chromium` or
`-- --project=mobile-webkit`. An existing compatible Chromium executable can be
selected with `GITMESH_TEST_CHROMIUM_EXECUTABLE`; an equivalent WebKit test
executable can be selected with `GITMESH_TEST_WEBKIT_EXECUTABLE`.

The test browser receives only an allowlisted set of runtime/library environment
variables, not the database URL, real keys, or integration tokens. Browser
contexts are disposable. Tests assert that local/session storage stays empty,
inspect downloaded test keys in memory and delete their temporary downloads.
Trace, video, automatic screenshots and Playwright's automatic ARIA error-context
snapshots are disabled because a rotation view contains a credential. The only
explicit screenshot is taken after sign-in clears that view.

Coverage includes copy and its denied-permission fallback, real download events
and contents, save acknowledgement, confirmation, old-key rejection,
cancellation, expired offers, competing tabs, refresh, and HTTP/network/unconfirmed
logout failures followed by successful retry.

WebKit emulation is not physical mobile Safari. A real iPhone check is still
needed for the iOS clipboard prompt and download/share-sheet experience. Do not
describe a browser project as verified unless it actually launched and passed.
