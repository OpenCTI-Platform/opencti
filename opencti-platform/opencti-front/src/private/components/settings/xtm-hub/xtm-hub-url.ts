const XTM_HUB_REGISTRATION_REDIRECT_PATH = 'redirect/opencti-registration';

/**
 * Page of this platform's registration on XTM Hub. The Hub resolves the platform id into the
 * registration page, and falls back to its home page when it cannot; without a platform id the
 * link goes to the Hub itself.
 */
export const buildXtmHubRegistrationUrl = (hubUrl: string, platformId?: string | null): string => {
  if (!platformId) return hubUrl;
  const query = new URLSearchParams({ platform_id: platformId });
  return `${hubUrl.replace(/\/+$/, '')}/${XTM_HUB_REGISTRATION_REDIRECT_PATH}?${query.toString()}`;
};
