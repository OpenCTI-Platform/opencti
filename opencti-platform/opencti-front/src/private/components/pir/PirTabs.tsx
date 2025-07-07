import React, { useState } from 'react';
import { Box, Tab, Tabs } from '@mui/material';
import { Link, useLocation } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import { useFormatter } from '../../../components/i18n';
import { PirTabsFragment$key } from './__generated__/PirTabsFragment.graphql';

const tabsFragment = graphql`
  fragment PirTabsFragment on Pir {
    id
  }
`;

interface PirTabsProps {
  data: PirTabsFragment$key
}

const PirTabs = ({ data }: PirTabsProps) => {
  const { id } = useFragment(tabsFragment, data);
  const { pathname } = useLocation();
  const { t_i18n } = useFormatter();
  const [index, setIndex] = useState(() => {
    if (pathname.endsWith('knowledge')) return 1;
    if (pathname.endsWith('ttps')) return 2;
    if (pathname.endsWith('analyses')) return 3;
    return 0;
  });

  return (
    <Box sx={{
      borderBottom: 1,
      borderColor: 'divider',
      marginBottom: 3,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
    }}
    >
      <Tabs value={index} onChange={(_, i) => setIndex(i)}>
        <Tab
          component={Link}
          label={t_i18n('Overview')}
          to={`/dashboard/pirs/${id}`}
        />
        <Tab
          component={Link}
          label={t_i18n('Knowledge')}
          to={`/dashboard/pirs/${id}/knowledge`}
        />
        <Tab
          component={Link}
          label={t_i18n('TTPs')}
          to={`/dashboard/pirs/${id}/ttps`}
        />
        <Tab
          component={Link}
          label={t_i18n('Analyses')}
          to={`/dashboard/pirs/${id}/analyses`}
        />
      </Tabs>
    </Box>
  );
};

export default PirTabs;
