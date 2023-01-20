import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import {
  BiotechOutlined,
  TipsAndUpdatesOutlined,
  TaskAltOutlined,
  WorkOutlineOutlined,
} from '@mui/icons-material';
import { Brain } from 'mdi-material-ui';
import { makeStyles } from '@mui/styles';
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

const TopMenuCases = () => {
  const { t } = useFormatter();
  const location = useLocation();
  const classes = useStyles();
  return (
    <div>
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
        {t('Incident response')}
      </Button>
      <Button
        component={Link}
        to="/dashboard/cases/feedbacks"
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
        disabled={true}
      >
        <Brain className={classes.icon} fontSize="small" />
        {t('RFIs')}
      </Button>
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
        {t('Feedbacks')}
      </Button>
      <Button
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
      </Button>
    </div>
  );
};

export default TopMenuCases;
