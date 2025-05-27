import { graphql, useFragment } from 'react-relay';
import React from 'react';
import { Typography } from '@mui/material';
import PirPopover from '@components/pir/PirPopover';
import { useNavigate } from 'react-router-dom';
import { PirHeaderFragment$key } from './__generated__/PirHeaderFragment.graphql';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';

const headerFragment = graphql`
  fragment PirHeaderFragment on Pir {
    id
    name
  }
`;

interface PirHeaderProps {
  data: PirHeaderFragment$key
}

const PirHeader = ({ data }: PirHeaderProps) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const { name, id } = useFragment(headerFragment, data);

  const breadcrumb = [
    { label: t_i18n('PIR'), link: '/dashboard/pirs' },
    { label: name, current: true },
  ];

  return (
    <>
      <Breadcrumbs elements={breadcrumb} />

      <div style={{ display: 'flex', alignItems: 'center' }}>
        <Typography variant="h1" sx={{ marginBottom: 0, flex: 1 }}>
          {name}
        </Typography>
        <PirPopover
          pirId={id}
          onDeleteComplete={() => navigate('/dashboard/pirs')}
        />
      </div>
    </>
  );
};

export default PirHeader;
