import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import { ChessKnight, DiamondOutline, LaptopAccount } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../components/i18n';
import { Theme } from '../../../components/Theme';
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
  const { t } = useFormatter();
  const location = useLocation();

  return (
    <div>
      {!useIsHiddenEntity('Threat-Actor-Group') && (
        <Button
          component={Link}
          to="/dashboard/threats/threat_actors_group"
          variant={
            location.pathname.includes(
              '/dashboard/threats/threat_actors_group',
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              '/dashboard/threats/threat_actors_group',
            )
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <LaptopAccount className={classes.icon} fontSize="small" />
          {t('Threat actors group')}
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
          color={
            location.pathname.includes(
              '/dashboard/threats/threat_actors_individual',
            )
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <LaptopAccount className={classes.icon} fontSize="small" />
          {t('Threat actors individual')}
        </Button>
      )}
      {!useIsHiddenEntity('Intrusion-Set') && (
        <Button
          component={Link}
          to="/dashboard/threats/intrusion_sets"
          variant={
            location.pathname.includes(
              '/dashboard/threats/intrusion_sets',
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              '/dashboard/threats/intrusion_sets',
            )
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <DiamondOutline className={classes.icon} fontSize="small" />
          {t('Intrusion sets')}
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
          color={
            location.pathname === '/dashboard/threats/campaigns'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <ChessKnight className={classes.icon} fontSize="small" />
          {t('Campaigns')}
        </Button>
      )}
    </div>
  );
};

export default TopMenuThreats;
