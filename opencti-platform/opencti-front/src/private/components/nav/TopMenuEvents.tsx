import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import { VisibilityOutlined, WifiTetheringOutlined } from '@mui/icons-material';
import { Fire } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '@mui/material/styles/createTheme';
import { useFormatter } from '../../../components/i18n';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';

const useStyles = makeStyles<Theme>((theme) => ({
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

const TopMenuEvents = () => {
  const classes = useStyles();
  const location = useLocation();
  const { t_i18n } = useFormatter();

  return (
    <>
      {!useIsHiddenEntity('Incident') && (
        <Button
          component={Link}
          to="/dashboard/events/incidents"
          variant={
            location.pathname.includes('/dashboard/events/incidents')
              ? 'contained'
              : 'text'
          }
          size="small"
          classes={{ root: classes.button }}
        >
          <Fire className={classes.icon} fontSize="small" />
          {t_i18n('Incidents')}
        </Button>
      )}
      {!useIsHiddenEntity('stix-sighting-relationship') && (
        <Button
          component={Link}
          to="/dashboard/events/sightings"
          variant={
            location.pathname.includes('/dashboard/events/sightings')
              ? 'contained'
              : 'text'
          }
          size="small"
          classes={{ root: classes.button }}
        >
          <VisibilityOutlined className={classes.icon} fontSize="small" />
          {t_i18n('Sightings')}
        </Button>
      )}
      {!useIsHiddenEntity('Observed-Data') && (
        <Button
          component={Link}
          to="/dashboard/events/observed_data"
          variant={
            location.pathname.includes('/dashboard/events/observed_data')
              ? 'contained'
              : 'text'
          }
          size="small"
          classes={{ root: classes.button }}
        >
          <WifiTetheringOutlined className={classes.icon} fontSize="small" />
          {t_i18n('Observed datas')}
        </Button>
      )}
    </>
  );
};

export default TopMenuEvents;
