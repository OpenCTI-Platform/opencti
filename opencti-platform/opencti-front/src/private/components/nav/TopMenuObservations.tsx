import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import { ArchiveOutline, HexagonOutline, ServerNetwork, ShieldSearch } from 'mdi-material-ui';
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

const TopMenuObservations = () => {
  const classes = useStyles();
  const location = useLocation();
  const { t_i18n } = useFormatter();

  return (
    <div>
      {!useIsHiddenEntity('Stix-Cyber-Observable') && (
        <Button
          component={Link}
          to="/dashboard/observations/observables"
          variant={
            location.pathname.includes('/dashboard/observations/observables')
              ? 'contained'
              : 'text'
          }
          size="small"
          classes={{ root: classes.button }}
        >
          <HexagonOutline className={classes.icon} fontSize="small" />
          {t_i18n('Observables')}
        </Button>
      )}
      {!useIsHiddenEntity('Artifact') && (
        <Button
          component={Link}
          to="/dashboard/observations/artifacts"
          variant={
            location.pathname.includes('/dashboard/observations/artifacts')
              ? 'contained'
              : 'text'
          }
          size="small"
          classes={{ root: classes.button }}
        >
          <ArchiveOutline className={classes.icon} fontSize="small" />
          {t_i18n('Artifacts')}
        </Button>
      )}
      {!useIsHiddenEntity('Indicator') && (
        <Button
          component={Link}
          to="/dashboard/observations/indicators"
          variant={
            location.pathname.includes('/dashboard/observations/indicators')
              ? 'contained'
              : 'text'
          }
          size="small"
          classes={{ root: classes.button }}
        >
          <ShieldSearch className={classes.icon} fontSize="small" />
          {t_i18n('Indicators')}
        </Button>
      )}
      {!useIsHiddenEntity('Infrastructure') && (
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
          classes={{ root: classes.button }}
        >
          <ServerNetwork className={classes.icon} fontSize="small" />
          {t_i18n('Infrastructures')}
        </Button>
      )}
    </div>
  );
};

export default TopMenuObservations;
