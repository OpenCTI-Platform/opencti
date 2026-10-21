import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import TopBannersManager from './TopBannersManager';

const banners = vi.hoisted(() => ({
  state: { showLicenseBanner: false, showTrialBanner: false, showRegisterBanner: false, showSmtpRefreshTokenBanner: false },
}));

vi.mock('../../utils/hooks/useTopBanner', () => ({ default: () => ({ ...banners.state, showThreatPulsePreviewBanner: false, height: 0 }) }));
vi.mock('../../utils/hooks/useAuth', () => ({ default: () => ({ settings: {} }) }));
vi.mock('./LicenseBanner', () => ({ default: () => <div data-testid="license-banner" /> }));
vi.mock('./xtm_hub/StartTrialBanner', () => ({ default: () => <div data-testid="trial-banner" /> }));
vi.mock('./xtm_hub/RegisterPlatformBanner', () => ({ default: () => <div data-testid="register-banner" /> }));
vi.mock('./settings/smtp_configuration/SmtpRefreshTokenBanner', () => ({ default: () => null }));
vi.mock('./common/threat_pulse/ThreatPulsePreviewBanner', () => ({ default: () => <div data-testid="threat-pulse-preview-banner" /> }));

describe('TopBannersManager', () => {
  afterEach(() => {
    banners.state = { showLicenseBanner: false, showTrialBanner: false, showRegisterBanner: false, showSmtpRefreshTokenBanner: false };
  });

  it('should show the Threat Pulse preview banner when no other banner is shown', () => {
    render(<TopBannersManager />);
    expect(screen.getByTestId('threat-pulse-preview-banner')).toBeDefined();
  });

  it.each([
    ['showLicenseBanner'],
    ['showTrialBanner'],
    ['showRegisterBanner'],
    ['showSmtpRefreshTokenBanner'],
  ])('should keep the Threat Pulse preview banner back while %s, never on top of it', (flag) => {
    banners.state = { ...banners.state, [flag]: true };
    render(<TopBannersManager />);
    expect(screen.queryByTestId('threat-pulse-preview-banner')).toBeNull();
  });
});
