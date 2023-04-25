import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import {
  BiotechOutlined,
  TipsAndUpdatesOutlined,
} from '@mui/icons-material';
import { makeStyles } from '@mui/styles';
import { Theme } from '@mui/material/styles/createTheme';
import { Brain } from 'mdi-material-ui';
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
          <BiotechOutlined className={classes.icon} fontSize="small" />
          {t('Cases - Incidents')}
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
          <Brain className={classes.icon} fontSize="small" />
          {t('Cases - RFIs')}
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
          <Brain className={classes.icon} fontSize="small" />
          {t('Cases - RFTs')}
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
          <TipsAndUpdatesOutlined className={classes.icon} fontSize="small" />
          {t('Cases - Feedbacks')}
        </Button>
      )}
      {/* <Button
        component={Link}
        to="/dashboard/cases/others"
        variant={
          location.pathname === '/dashboard/cases/others' ? 'contained' : 'text'
        }
        size="small"
        color={
          location.pathname === '/dashboard/cases/others'
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={true}
      >
        <WorkOutlineOutlined className={classes.icon} fontSize="small" />
        {t('Others')}
      </Button>
      <Button
        component={Link}
        to="/dashboard/cases/feedbacks"
        variant={
          location.pathname === '/dashboard/cases/tasks' ? 'contained' : 'text'
        }
        size="small"
        color={
          location.pathname === '/dashboard/cases/tasks'
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={true}
      >
        <TaskAltOutlined className={classes.icon} fontSize="small" />
        {t('Tasks')}
      </Button> */}
    </div>
  );
};

export default TopMenuCases;
