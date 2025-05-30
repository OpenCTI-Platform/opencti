import { graphql, useFragment } from 'react-relay';
import React, { useState } from 'react';
import { Box, Button, Typography } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import PirDeletion from '@components/pir/PirDeletion';
import PirPopover from './PirPopover';
import PirEdition from './PirEdition';
import { PirHeaderFragment$key } from './__generated__/PirHeaderFragment.graphql';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { PirEditionFragment$key } from './__generated__/PirEditionFragment.graphql';

const headerFragment = graphql`
  fragment PirHeaderFragment on Pir {
    id
    name
  }
`;

interface PirHeaderProps {
  data: PirHeaderFragment$key
  editionData: PirEditionFragment$key
}

const PirHeader = ({ data, editionData }: PirHeaderProps) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const { name, id } = useFragment(headerFragment, data);

  const [isFormOpen, setFormOpen] = useState(false);

  const breadcrumb = [
    { label: t_i18n('PIR'), link: '/dashboard/pirs' },
    { label: name, current: true },
  ];

  return (
    <PirDeletion
      pirId={id}
      onDeleteComplete={() => navigate('/dashboard/pirs')}
    >
      {({ handleOpenDelete, deleting }) => (
        <>
          <Breadcrumbs elements={breadcrumb} />

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="h1" sx={{ marginBottom: 0, flex: 1 }}>
              {name}
            </Typography>

            <Button
              onClick={() => setFormOpen(true)}
              color="primary"
              variant="contained"
              aria-label={t_i18n('Update')}
              title={t_i18n('Update')}
            >
              {t_i18n('Update')}
            </Button>

            <PirPopover
              deleting={deleting}
              handleOpenDelete={handleOpenDelete}
            />
          </Box>

          <PirEdition
            isOpen={isFormOpen}
            onClose={() => setFormOpen(false)}
            data={editionData}
            deleting={deleting}
            handleOpenDelete={handleOpenDelete}
          />
        </>
      )}
    </PirDeletion>
  );
};

export default PirHeader;
