import { useFormatter } from '../../../../components/i18n';
import React, { useState } from 'react';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { Stack } from '@mui/material';
import TitleMainEntity from '@common/typography/TitleMainEntity';
import Button from '@common/button/Button';
import { graphql, useFragment } from 'react-relay';
import SSODefinitionEdition from '@components/settings/sso_definitions/SSODefinitionEdition';
import { SSODefinitionHeaderFragment$key } from '@components/settings/sso_definitions/__generated__/SSODefinitionHeaderFragment.graphql';
import { SSODefinitionEditionFragment$key } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionFragment.graphql';
import SSODefinitionPopover from '@components/settings/sso_definitions/SSODefinitionPopover';

export const headerFragment = graphql`
  fragment SSODefinitionHeaderFragment on SingleSignOn {
    id
    name
    strategy
    ...SSODefinitionPopoverFragment
  }
`;

interface SSODefinitionHeaderProps {
  data: SSODefinitionHeaderFragment$key;
  editionData: SSODefinitionEditionFragment$key;
}

const SSODefinitionHeader = (
  { data, editionData }: SSODefinitionHeaderProps,
) => {
  const { t_i18n } = useFormatter();
  const sso = useFragment(headerFragment, data);
  const { name, strategy } = sso;

  const [isEditionOpen, setIsEditionOpen] = useState(false);

  const breadcrumb = [
    { label: t_i18n('SSO Definitions'), link: '/dashboard/settings/accesses/single_sign_ons' },
    { label: strategy, current: true },
  ];

  return (
    <>
      <Breadcrumbs elements={breadcrumb} />
      <>
        <Stack direction="row" alignItems="center" gap={0.5} marginBottom={3}>
          <>
            <TitleMainEntity sx={{ flex: 1 }}>
              {name}
            </TitleMainEntity>
            <Button
              onClick={() => setIsEditionOpen(true)}
              aria-label={t_i18n('Update')}
              title={t_i18n('Update')}
            >
              {t_i18n('Update')}
            </Button>
            <SSODefinitionPopover data={sso} />
          </>
        </Stack>
        <SSODefinitionEdition
          isOpen={isEditionOpen}
          onClose={() => setIsEditionOpen(false)}
          selectedStrategy={strategy}
          data={editionData}
        />
      </>
    </>
  );
};

export default SSODefinitionHeader;
