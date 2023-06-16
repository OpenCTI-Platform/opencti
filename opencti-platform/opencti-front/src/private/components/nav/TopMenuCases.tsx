import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import {
  BriefcaseEyeOutline,
  BriefcaseSearchOutline,
  BriefcaseRemoveOutline,
  BriefcaseEditOutline,
} from 'mdi-material-ui';
import { makeStyles } from '@mui/styles';
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

const TopMenuCases = () => {
  const { t } = useFormatter();
  const location = useLocation();
  const classes = useStyles();
  return (
    <div>
      {!useIsHiddenEntity('Case-Incident') && (
        <Button
          component={Link}
          to="/dashboard/cases/incidents"
          variant={
            location.pathname === '/dashboard/cases/incidents'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/cases/incidents'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <BriefcaseEyeOutline className={classes.icon} fontSize="small" />
          {t('Incident response')}
        </Button>
      )}
      {!useIsHiddenEntity('Case-Rfi') && (
        <Button
          component={Link}
          to="/dashboard/cases/rfis"
          variant={
            location.pathname === '/dashboard/cases/rfis' ? 'contained' : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/cases/rfis'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <BriefcaseSearchOutline className={classes.icon} fontSize="small" />
          {t('Requests for information')}
        </Button>
      )}
      {!useIsHiddenEntity('Case-Rft') && (
        <Button
          component={Link}
          to="/dashboard/cases/rfts"
          variant={
            location.pathname === '/dashboard/cases/rfts' ? 'contained' : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/cases/rfts'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <BriefcaseRemoveOutline className={classes.icon} fontSize="small" />
          {t('Requests for takedown')}
        </Button>
      )}
      {!useIsHiddenEntity('Feedback') && (
        <Button
          component={Link}
          to="/dashboard/cases/feedbacks"
          variant={
            location.pathname === '/dashboard/cases/feedbacks'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/cases/feedbacks'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <BriefcaseEditOutline className={classes.icon} fontSize="small" />
          {t('Feedbacks')}
        </Button>
      )}
    </div>
  );
};

export default TopMenuCases;
