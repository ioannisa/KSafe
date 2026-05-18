// Headless-Chrome config for Kotlin/JS + Kotlin/WASM browser tests
// (`:ksafe:jsBrowserTest`, `:ksafe:wasmJsBrowserTest`).
//
// CI runs Chrome in a sandboxless container, so a custom launcher with
// `--no-sandbox` is required. Locally this is harmless: developers with a
// normal Chrome still run headless. Chrome location comes from the CHROME_BIN
// env var (set by the CI job).
config.set({
    customLaunchers: {
        ChromeHeadlessNoSandbox: {
            base: 'ChromeHeadless',
            flags: [
                '--no-sandbox',
                '--disable-gpu',
                '--disable-dev-shm-usage',
            ],
        },
    },
    browsers: ['ChromeHeadlessNoSandbox'],
    singleRun: true,
    captureTimeout: 120000,
    browserDisconnectTimeout: 60000,
    browserDisconnectTolerance: 2,
    browserNoActivityTimeout: 120000,
});
