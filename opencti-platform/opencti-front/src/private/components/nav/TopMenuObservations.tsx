import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import { ArchiveOutline, HexagonOutline, ServerNetwork, ShieldSearch } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '@mui/material/styles/createTheme';
import { useFormatter } from '../../../components/i18n';

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

const TopMenuObservations = () => {
  const classes = useStyles();
  const location = useLocation();
  const { t } = useFormatter();

  return (
    <div>
      <Button
        component={Link}
        to="/dashboard/observations/observables"
        variant={
          location.pathname.includes('/dashboard/observations/observables')
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname.includes('/dashboard/observations/observables')
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        <HexagonOutline className={classes.icon} fontSize="small" />
        {t('Observables')}
      </Button>
      <Button
        component={Link}
        to="/dashboard/observations/artifacts"
        variant={
          location.pathname.includes('/dashboard/observations/artifacts')
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname.includes('/dashboard/observations/artifacts')
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        <ArchiveOutline className={classes.icon} fontSize="small" />
        {t('Artifacts')}
      </Button>
        <Button
          component={Link}
          to="/dashboard/observations/indicators"
          variant={
            location.pathname.includes('/dashboard/observations/indicators')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/dashboard/observations/indicators')
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <ShieldSearch className={classes.icon} fontSize="small" />
          {t('Indicators')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/observations/infrastructures"
          variant={
            location.pathname.includes(
              '/dashboard/observations/infrastructures',
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              '/dashboard/observations/infrastructures',
            )
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <ServerNetwork className={classes.icon} fontSize="small" />
          {t('Infrastructures')}
        </Button>
    </div>
  );
};

export default TopMenuObservations;
