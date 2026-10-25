// Shared launch selection for test tooling; product runtime does not import this.
export function browserLaunchOptions(env = process.env) {
  if (env.IDP_UI_PROFILE === 'ci-functional') {
    if (env.IDP_UI_HEADED === '1' || env.IDP_UI_N2_LAYOUT === '1') {
      throw new Error('CI functional profile forbids headed and layout modes');
    }
    return { channel: 'chromium', headless: true };
  }
  return {
    headless: env.IDP_UI_HEADED !== '1',
    executablePath: env.IDP_UI_BROWSER_EXECUTABLE,
  };
}
