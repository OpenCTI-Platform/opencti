import React, { useState } from 'react';
import { Box, Tab, Tabs } from '@mui/material';
import { Link, useLocation } from 'react-router-dom';
import { useFormatter } from '../../../components/i18n';

interface PirTabsProps {
  pirId: string
}

const PirTabs = ({ pirId }: PirTabsProps) => {
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
          to={`/dashboard/pirs/${pirId}`}
        />
        <Tab
          component={Link}
          label={t_i18n('Knowledge')}
          to={`/dashboard/pirs/${pirId}/knowledge`}
        />
        <Tab
          component={Link}
          label={t_i18n('TTPs')}
          to={`/dashboard/pirs/${pirId}/ttps`}
        />
        <Tab
          component={Link}
          label={t_i18n('Analyses')}
          to={`/dashboard/pirs/${pirId}/analyses`}
        />
      </Tabs>
    </Box>
  );
};

export default PirTabs;
