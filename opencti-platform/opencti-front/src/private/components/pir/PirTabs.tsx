import React, { ReactNode, useState } from 'react';
import { Box, Tab, Tabs } from '@mui/material';
import { useFormatter } from '../../../components/i18n';

interface ChildrenProps {
  index: number
}

interface PirTabsProps {
  children: (props: ChildrenProps) => ReactNode
}

const PirTabs = ({ children }: PirTabsProps) => {
  const { t_i18n } = useFormatter();
  const [index, setIndex] = useState(0);

  return (
    <>
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
          <Tab label={t_i18n('Overview')} />
          <Tab label={t_i18n('Knowledge')} />
          <Tab label={t_i18n('TTPS')} />
          <Tab label={t_i18n('Analyses')} />
        </Tabs>
      </Box>

      {children({ index })}
    </>
  );
};

export default PirTabs;
