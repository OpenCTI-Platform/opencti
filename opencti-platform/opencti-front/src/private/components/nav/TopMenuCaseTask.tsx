import React, { FunctionComponent } from 'react';
import { Link, useLocation, useParams } from 'react-router-dom';
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

const TopMenuCaseTask: FunctionComponent = () => {
  const location = useLocation();
  const { t } = useFormatter();
  const classes = styles();
  const { caseId } = useParams() as { caseId: string };
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
        {t('Case Tasks')}
      </Button>
      <ArrowForwardIosOutlined
        color="primary"
        classes={{ root: classes.arrow }}
      />
      <Button
        component={Link}
        to={`/dashboard/cases/tasks/${caseId}`}
        variant={
          location.pathname === `/dashboard/cases/tasks/${caseId}`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname === `/dashboard/cases/tasks/${caseId}`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        {t('Overview')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/cases/tasks/${caseId}/files`}
        variant={
          location.pathname === `/dashboard/cases/tasks/${caseId}/files`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname === `/dashboard/cases/tasks/${caseId}/files`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        {t('Data')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/cases/tasks/${caseId}/history`}
        variant={
          location.pathname === `/dashboard/cases/tasks/${caseId}/history`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname === `/dashboard/cases/tasks/${caseId}/history`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        {t('History')}
      </Button>
    </div>
  );
};

export default TopMenuCaseTask;
