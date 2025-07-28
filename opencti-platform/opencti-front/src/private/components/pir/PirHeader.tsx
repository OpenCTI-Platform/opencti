import { graphql, useFragment } from 'react-relay';
import React, { useState } from 'react';
import { Box, Button, Typography } from '@mui/material';
import PirPopover from './PirPopover';
import PirEdition from './PirEdition';
import { PirHeaderFragment$key } from './__generated__/PirHeaderFragment.graphql';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { PirEditionFragment$key } from './__generated__/PirEditionFragment.graphql';

const headerFragment = graphql`
  fragment PirHeaderFragment on Pir {
    name
    ...PirPopoverFragment
  }
`;

interface PirHeaderProps {
  data: PirHeaderFragment$key
  editionData: PirEditionFragment$key
}

const PirHeader = ({ data, editionData }: PirHeaderProps) => {
  const { t_i18n } = useFormatter();
  const pir = useFragment(headerFragment, data);
  const { name } = pir;

  const [isFormOpen, setFormOpen] = useState(false);

  const breadcrumb = [
    { label: t_i18n('PIR'), link: '/dashboard/pirs' },
    { label: name, current: true },
  ];

  return (
    <>
      <Breadcrumbs elements={breadcrumb} />

      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <Typography variant="h1" sx={{ marginBottom: 0, flex: 1 }}>
          {name}
        </Typography>

        <PirPopover data={pir} />

        <Button
          onClick={() => setFormOpen(true)}
          color="primary"
          variant="contained"
          aria-label={t_i18n('Update')}
          title={t_i18n('Update')}
        >
          {t_i18n('Update')}
        </Button>
      </Box>

      <PirEdition
        isOpen={isFormOpen}
        onClose={() => setFormOpen(false)}
        data={editionData}
      />
    </>
  );
};

export default PirHeader;
