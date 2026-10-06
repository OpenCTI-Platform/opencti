import React from 'react';
import { Link } from 'react-router';
import { Box } from '@mui/material';
import { Alert, Button } from '@filigran/design-system';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import PageContainer from '../../../../components/PageContainer';
import { useFormatter } from '../../../../components/i18n';

interface HubNoAccessProps {
  /** The English source label of the hub, the current entry of the breadcrumb. */
  hub: string;
  /** The English source labels of the breadcrumb entries above the hub, if any. */
  parents?: string[];
  /** Where the reader goes back to, and its English source label. */
  back: { link: string; label: string };
}

/**
 * Shown to a reader who reaches a hub, from a shared link or a notification, with none of its entries
 * available: says so and leads back, rather than redirecting without a word.
 */
const HubNoAccess = ({ hub: hubLabel, parents = [], back }: HubNoAccessProps) => {
  const { t_i18n } = useFormatter();
  const hub = t_i18n(hubLabel);
  return (
    <PageContainer withRightMenu={false}>
      {/* The "/" separator sets the line height of a breadcrumb: a single entry has none, so its row keeps the line box
          of that text size to start the alert where the first block of every other page starts */}
      <Box sx={{ fontSize: 'var(--text-content-base)', lineHeight: 'var(--leading-content-base)', '& > nav': { minHeight: '1lh' } }}>
        <Breadcrumbs
          elements={[...parents.map((label) => ({ label: t_i18n(label) })), { label: hub, current: true }]}
        />
      </Box>
      <Alert
        severity="info"
        data-testid="hub-no-access"
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
