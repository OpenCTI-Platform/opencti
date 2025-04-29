import { graphql, useFragment } from 'react-relay';
import React from 'react';
import { Typography } from '@mui/material';
import { PirHeaderFragment$key } from './__generated__/PirHeaderFragment.graphql';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';

const headerFragment = graphql`
  fragment PirHeaderFragment on PIR {
    name
  }
`;

interface PirHeaderProps {
  data: PirHeaderFragment$key
}

const PirHeader = ({ data }: PirHeaderProps) => {
  const { t_i18n } = useFormatter();
  const pir = useFragment(headerFragment, data);

  const breadcrumb = [
    { label: t_i18n('PIR'), link: '/dashboard/pirs' },
    { label: pir.name, current: true },
  ];

  return (
    <>
      <Breadcrumbs elements={breadcrumb} />
      <Typography variant="h1">{pir.name}</Typography>
    </>
  );
};

export default PirHeader;
