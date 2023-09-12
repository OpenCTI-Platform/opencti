import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import { ArrowForwardIosOutlined, TaskAltOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../components/i18n';
import { Theme } from '../../../components/Theme';

const styles = makeStyles<Theme>((theme) => ({
  buttonHome: {
    marginRight: theme.spacing(2),
    padding: '0 5px 0 5px',
    minHeight: 20,
    textTransform: 'none',
  },
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
  arrow: {
    verticalAlign: 'middle',
    marginRight: 10,
  },
}));

const TopMenuTask = ({ id: taskId }: { id: string }) => {
  const location = useLocation();
  const { t } = useFormatter();
  const classes = styles();
  return (
    <div>
      <Button
        component={Link}
        to="/dashboard/cases/tasks"
        variant="contained"
        size="small"
        color="primary"
        classes={{ root: classes.buttonHome }}
      >
        <TaskAltOutlined className={classes.icon} fontSize="small" />
        {t('Tasks')}
      </Button>
      <ArrowForwardIosOutlined
        color="primary"
        classes={{ root: classes.arrow }}
      />
      <Button
        component={Link}
        to={`/dashboard/cases/tasks/${taskId}`}
        variant={
          location.pathname === `/dashboard/cases/tasks/${taskId}`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname === `/dashboard/cases/tasks/${taskId}`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!taskId}
      >
        {t('Overview')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/cases/tasks/${taskId}/files`}
        variant={
          location.pathname === `/dashboard/cases/tasks/${taskId}/files`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname === `/dashboard/cases/tasks/${taskId}/files`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!taskId}
      >
        {t('Data')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/cases/tasks/${taskId}/history`}
        variant={
          location.pathname === `/dashboard/cases/tasks/${taskId}/history`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname === `/dashboard/cases/tasks/${taskId}/history`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!taskId}
      >
        {t('History')}
      </Button>
    </div>
  );
};

export default TopMenuTask;
