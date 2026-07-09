import React, { Suspense, useEffect } from 'react';
import { graphql, PreloadedQuery, useQueryLoader, usePreloadedQuery } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import TopBanner from '../../../../components/TopBanner';
import { useFormatter } from '../../../../components/i18n';
import { getSmtpRefreshTokenBannerState } from '../../../../utils/bannerUtils';
import { dispatch } from '../../../../utils/hooks/useBus';
import { SMTP_REFRESH_TOKEN_BANNER_VISIBLE_BUS } from '../../../../utils/bannerConstants';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';
import { SmtpRefreshTokenBannerQuery } from './__generated__/SmtpRefreshTokenBannerQuery.graphql';

const smtpRefreshTokenBannerQuery = graphql`
  query SmtpRefreshTokenBannerQuery {
    smtpConfiguration {
      auth_type
      oauth_refresh_token_expires_at
    }
  }
`;

interface SmtpRefreshTokenBannerContentProps {
  queryRef: PreloadedQuery<SmtpRefreshTokenBannerQuery>;
}

const SmtpRefreshTokenBannerContent = ({ queryRef }: SmtpRefreshTokenBannerContentProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const { smtpConfiguration } = usePreloadedQuery(smtpRefreshTokenBannerQuery, queryRef);

  const bannerState = getSmtpRefreshTokenBannerState(
    smtpConfiguration?.auth_type,
    smtpConfiguration?.oauth_refresh_token_expires_at,
  );
  const isVisible = bannerState !== 'none';

  // Let useTopBanner know this banner's visibility so the shared top offset/height
  // stays correct, since this banner resolves its own visibility from a dedicated
  // query instead of the globally preloaded Settings.
  useEffect(() => {
    dispatch(SMTP_REFRESH_TOKEN_BANNER_VISIBLE_BUS, isVisible);
    return () => dispatch(SMTP_REFRESH_TOKEN_BANNER_VISIBLE_BUS, false);
  }, [isVisible]);

  if (!isVisible) return null;

  const bannerText = bannerState === 'expired'
    ? t_i18n('The SMTP OAuth2 refresh token has expired. Email sending is likely interrupted, renew it as soon as possible.')
    : t_i18n('The SMTP OAuth2 refresh token is about to expire. Renew it to avoid interrupting email sending.');

  return (
    <TopBanner
      bannerColor={bannerState === 'expired' ? 'red' : 'yellow'}
      bannerText={bannerText}
      buttonText={t_i18n('Configure SMTP')}
      onButtonClick={() => navigate('/dashboard/settings/accesses/smtp')}
    />
  );
};

// Not capability-gated at the query level (backend already gates smtpConfiguration
// with @auth(for: [SETTINGS_SETACCESSES])) — the frontend check below simply avoids
// firing an unnecessary (and error-producing) request for users without the capability
// or when the SMTP_CONFIGURATION feature flag is disabled (backend then rejects the query).
const SmtpRefreshTokenBanner = () => {
  const isGranted = useGranted([SETTINGS_SETACCESSES]);
  const { isFeatureEnable } = useHelper();
  const isSmtpConfigurationEnabled = isFeatureEnable('SMTP_CONFIGURATION');
  const [queryRef, loadQuery] = useQueryLoader<SmtpRefreshTokenBannerQuery>(smtpRefreshTokenBannerQuery);

  useEffect(() => {
    if (isGranted && isSmtpConfigurationEnabled) {
      loadQuery({}, { fetchPolicy: 'store-and-network' });
    }
  }, [isGranted, isSmtpConfigurationEnabled]);

  if (!isGranted || !isSmtpConfigurationEnabled || !queryRef) return null;

  return (
    <Suspense fallback={null}>
      <SmtpRefreshTokenBannerContent queryRef={queryRef} />
    </Suspense>
  );
};

export default SmtpRefreshTokenBanner;
