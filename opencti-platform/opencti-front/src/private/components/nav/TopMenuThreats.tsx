import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import { AccountMultipleOutline, ChessKnight, DiamondOutline, LaptopAccount } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
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

const TopMenuThreats = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const location = useLocation();

  return (
    <>
      {!useIsHiddenEntity('Threat-Actor-Group') && (
        <Button
          component={Link}
          to="/dashboard/threats/threat_actors_group"
          variant={
            location.pathname.includes('/dashboard/threats/threat_actors_group')
              ? 'contained'
              : 'text'
          }
          size="small"
          classes={{ root: classes.button }}
        >
          <AccountMultipleOutline className={classes.icon} fontSize="small" />
          {t_i18n('Threat actors (group)')}
        </Button>
      )}
      {!useIsHiddenEntity('Threat-Actor-Individual') && (
        <Button
          component={Link}
          to="/dashboard/threats/threat_actors_individual"
          variant={
            location.pathname.includes(
              '/dashboard/threats/threat_actors_individual',
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          classes={{ root: classes.button }}
        >
          <LaptopAccount className={classes.icon} fontSize="small" />
          {t_i18n('Threat actors (individual)')}
        </Button>
      )}
      {!useIsHiddenEntity('Intrusion-Set') && (
        <Button
          component={Link}
          to="/dashboard/threats/intrusion_sets"
          variant={
            location.pathname.includes('/dashboard/threats/intrusion_sets')
              ? 'contained'
              : 'text'
          }
          size="small"
          classes={{ root: classes.button }}
        >
          <DiamondOutline className={classes.icon} fontSize="small" />
          {t_i18n('Intrusion sets')}
        </Button>
      )}
      {!useIsHiddenEntity('Campaign') && (
        <Button
          component={Link}
          to="/dashboard/threats/campaigns"
          variant={
            location.pathname.includes('/dashboard/threats/campaigns')
              ? 'contained'
              : 'text'
          }
          size="small"
          classes={{ root: classes.button }}
        >
          <ChessKnight className={classes.icon} fontSize="small" />
          {t_i18n('Campaigns')}
        </Button>
      )}
    </>
  );
};

export default TopMenuThreats;
