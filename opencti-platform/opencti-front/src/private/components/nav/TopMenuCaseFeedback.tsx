import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import { ArrowForwardIosOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { BriefcaseEditOutline } from 'mdi-material-ui';
import { useFormatter } from '../../../components/i18n';
import { Theme } from '../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
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

const TopMenuCaseFeedback = ({ id: caseId }: { id: string }) => {
  const location = useLocation();
  const { t } = useFormatter();
  const classes = useStyles();
  return (
    <div>
      <Button
        component={Link}
        to="/dashboard/cases/feedbacks"
        variant="contained"
        size="small"
        color="primary"
        classes={{ root: classes.buttonHome }}
      >
        <BriefcaseEditOutline className={classes.icon} fontSize="small" />
        {t('Feedbacks')}
      </Button>
      <ArrowForwardIosOutlined
        color="primary"
        classes={{ root: classes.arrow }}
      />
      <Button
        component={Link}
        to={`/dashboard/cases/feedbacks/${caseId}`}
        variant={
          location.pathname === `/dashboard/cases/feedbacks/${caseId}`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname === `/dashboard/cases/feedbacks/${caseId}`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!caseId}
      >
        {t('Overview')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/cases/feedbacks/${caseId}/content`}
        variant={
          location.pathname === `/dashboard/cases/feedbacks/${caseId}/content`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname === `/dashboard/cases/feedbacks/${caseId}/content`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!caseId}
      >
        {t('Content')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/cases/feedbacks/${caseId}/files`}
        variant={
          location.pathname === `/dashboard/cases/feedbacks/${caseId}/files`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname === `/dashboard/cases/feedbacks/${caseId}/files`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!caseId}
      >
        {t('Data')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/cases/feedbacks/${caseId}/history`}
        variant={
          location.pathname === `/dashboard/cases/feedbacks/${caseId}/history`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname === `/dashboard/cases/feedbacks/${caseId}/history`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!caseId}
      >
        {t('History')}
      </Button>
    </div>
  );
};

export default TopMenuCaseFeedback;
