import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import { BriefcaseEyeOutline, BriefcaseSearchOutline, BriefcaseRemoveOutline, BriefcaseEditOutline } from 'mdi-material-ui';
import { TaskAltOutlined } from '@mui/icons-material';
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
  const { t_i18n } = useFormatter();
  const location = useLocation();
  const classes = useStyles();
  return (
    <div>
      {!useIsHiddenEntity('Case-Incident') && (
        <Button
          component={Link}
          to="/dashboard/cases/incidents"
          variant={
            location.pathname.includes('/dashboard/cases/incidents')
              ? 'contained'
              : 'text'
          }
          size="small"
          classes={{ root: classes.button }}
        >
          <BriefcaseEyeOutline className={classes.icon} fontSize="small" />
          {t_i18n('Incident responses')}
        </Button>
      )}
      {!useIsHiddenEntity('Case-Rfi') && (
        <Button
          component={Link}
          to="/dashboard/cases/rfis"
          variant={
            location.pathname.includes('/dashboard/cases/rfis')
              ? 'contained'
              : 'text'
          }
          size="small"
          classes={{ root: classes.button }}
        >
          <BriefcaseSearchOutline className={classes.icon} fontSize="small" />
          {t_i18n('Requests for information')}
        </Button>
      )}
      {!useIsHiddenEntity('Case-Rft') && (
        <Button
          component={Link}
          to="/dashboard/cases/rfts"
          variant={
            location.pathname.includes('/dashboard/cases/rfts')
              ? 'contained'
              : 'text'
          }
          size="small"
          classes={{ root: classes.button }}
        >
          <BriefcaseRemoveOutline className={classes.icon} fontSize="small" />
          {t_i18n('Requests for takedown')}
        </Button>
      )}
      {!useIsHiddenEntity('Task') && (
        <Button
          component={Link}
          to="/dashboard/cases/tasks"
          variant={
            location.pathname.includes('/dashboard/cases/tasks')
              ? 'contained'
              : 'text'
          }
          size="small"
          classes={{ root: classes.button }}
        >
          <TaskAltOutlined className={classes.icon} fontSize="small" />
          {t_i18n('Tasks')}
        </Button>
      )}
      {!useIsHiddenEntity('Feedback') && (
        <Button
          component={Link}
          to="/dashboard/cases/feedbacks"
          variant={
            location.pathname.includes('/dashboard/cases/feedbacks')
              ? 'contained'
              : 'text'
          }
          size="small"
          classes={{ root: classes.button }}
        >
          <BriefcaseEditOutline className={classes.icon} fontSize="small" />
          {t_i18n('Feedbacks')}
        </Button>
      )}
    </div>
  );
};

export default TopMenuCases;
