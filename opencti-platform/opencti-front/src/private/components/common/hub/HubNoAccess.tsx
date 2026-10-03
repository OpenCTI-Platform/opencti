import React from 'react';
import { Link } from 'react-router';
import { Alert, Button } from '@filigran/design-system';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import PageContainer from '../../../../components/PageContainer';
import { useFormatter } from '../../../../components/i18n';

interface HubNoAccessProps {
  /** The breadcrumb of the hub, in English source strings, the last one being the hub. */
  trail: string[];
  /** Where the reader goes back to, and its English source label. */
  back: { link: string; label: string };
}

/**
 * Shown to a reader who reaches a hub, from a shared link or a notification, with none of its entries
 * available: says so and leads back, rather than redirecting without a word.
 */
const HubNoAccess = ({ trail, back }: HubNoAccessProps) => {
  const { t_i18n } = useFormatter();
  const hub = t_i18n(trail[trail.length - 1]);
  return (
    <PageContainer withRightMenu={false} withGap>
      <Breadcrumbs
        elements={trail.map((label, index) => ({ label: t_i18n(label), current: index === trail.length - 1 }))}
      />
      <Alert
        severity="info"
        title={t_i18n('Nothing in {hub} is available to you', { values: { hub } })}
        description={t_i18n('Its pages are hidden on this platform or need a permission your account does not have. Ask your administrator if you need them.')}
        action={(
          <Button priority="secondary" size="sm" asChild>
            <Link to={back.link}>{t_i18n(back.label)}</Link>
          </Button>
        )}
      />
    </PageContainer>
  );
};

export default HubNoAccess;
