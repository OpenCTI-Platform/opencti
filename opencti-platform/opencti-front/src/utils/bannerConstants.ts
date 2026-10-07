export const REGISTER_BANNER_DISMISSED_KEY = 'register-banner-dismissed';
export const REGISTER_BANNER_DISMISSED_BUS = `${REGISTER_BANNER_DISMISSED_KEY}_bus`;

// Notifies useTopBanner whenever SmtpRefreshTokenBanner's own visibility changes,
export const SMTP_REFRESH_TOKEN_BANNER_VISIBLE_BUS = 'smtp-refresh-token-banner-visible_bus';

// The Threat Pulse preview banner is dismissed per user.
export const threatPulsePreviewBannerDismissKey = (userId: string) => `threat-pulse-preview-banner-dismissed-${userId}`;
export const THREAT_PULSE_PREVIEW_BANNER_DISMISSED_BUS = 'threat-pulse-preview-banner-dismissed_bus';
export const THREAT_PULSE_PREVIEW_BANNER_VISIBLE_BUS = 'threat-pulse-preview-banner-visible_bus';
