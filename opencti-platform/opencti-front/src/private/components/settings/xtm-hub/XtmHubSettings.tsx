import React from 'react';
import Paper from '@mui/material/Paper';
import { Grid2, List, Typography } from '@mui/material';
import Box from '@mui/material/Box';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import XtmHubTab from './XtmHubTab';

const XtmHubSettings = () => {
  const { t_i18n } = useFormatter();
  return <section>
    <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('XTM Hub'), current: true }]} />
    <Grid2 container spacing={3}>
      <Grid2 size={6}>
        <Paper variant="outlined" sx={{ padding: '20px', borderRadius: 1, marginTop: 1 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
            <Typography variant="h2" sx={{ lineHeight: '1.5', textTransform: 'none' }}> {t_i18n('XTM Hub is the focal point to find every Services and Products.')}</Typography>
            <XtmHubTab/>
          </Box>
          <Box sx={{ color: '#FFFFFFCC' }}>
            {t_i18n('By registering your OCTI instance, you\'ll be able to:')}
            <List sx={{ listStyleType: 'disc', marginLeft: 4 }}>
              <li>{t_i18n('deploy in one-click Threats intelligence ressources')}</li>
              <li>{t_i18n('see metrics on your instance')}</li>
            </List>
          </Box>
        </Paper>
      </Grid2>
    </Grid2>

  </section>;
};

export default XtmHubSettings;
