import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../components/i18n';

const useStyles = makeStyles((theme) => ({
  button: {
    marginRight: theme.spacing(2),
    padding: '0 5px 0 5px',
    minHeight: 20,
    minWidth: 20,
    textTransform: 'none',
  },
  icon: {
    marginRight: theme.spacing(1),
  },
}));

const TopMenuNotifications = () => {
  const location = useLocation();
  const { t } = useFormatter();
  const classes = useStyles();
  return (
    <div>
      <Button
        component={Link}
        to="/dashboard/profile/notifications"
        size="small"
        variant={
          location.pathname === '/dashboard/profile/notifications'
            ? 'contained'
            : 'text'
        }
        color={
          location.pathname === '/dashboard/profile/notifications'
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        {t('Notifications')}
      </Button>
      <Button
        component={Link}
        to="/dashboard/profile/triggers"
        size="small"
        variant={
          location.pathname === '/dashboard/profile/triggers'
            ? 'contained'
            : 'text'
        }
        color={
          location.pathname === '/dashboard/profile/triggers'
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        {t('Triggers and digests')}
      </Button>
    </div>
  );
};

export default TopMenuNotifications;
