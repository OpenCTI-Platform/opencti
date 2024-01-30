import { useTheme } from '@mui/styles';
import AppBar from '@mui/material/AppBar';
import React from 'react';
import Toolbar from '@mui/material/Toolbar';
import Button from '@mui/material/Button';
import { useFormatter } from '../../components/i18n';
import type { Theme } from '../../components/Theme';

const PublicTopBar = () => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  return (
    <AppBar
      position="relative"
      elevation={1}
      sx={{
        zIndex: theme.zIndex.drawer + 1,
        background: theme.palette.background.nav,
        paddingTop: theme.spacing(0.2),
      }}
    >
      <Toolbar>
        <img
          src={theme.logo}
          alt="logo"
          height={35}
        />
        <div style={{ marginLeft: '30px' }}>
          <Button
            variant="contained"
            size="small"
            sx={{
              padding: '0 5px',
              textTransform: 'none',
              pointerEvents: 'none',
            }}
          >
            {t_i18n('Public dashboard')}
          </Button>
        </div>
      </Toolbar>
    </AppBar>
  );
};

export default PublicTopBar;
