import React, { FunctionComponent } from 'react';
import { Link, useLocation, useParams } from 'react-router-dom';
import Button from '@mui/material/Button';
import { ArrowForwardIosOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { BriefcaseRemoveOutline } from 'mdi-material-ui';
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

const TopMenuCaseRft: FunctionComponent = () => {
  const location = useLocation();
  const { t } = useFormatter();
  const classes = styles();
  const { caseId } = useParams() as { caseId: string };
  return (
    <div>
      <Button
        component={Link}
        to="/dashboard/cases/rfts"
        variant="contained"
        size="small"
        color="primary"
        classes={{ root: classes.buttonHome }}
      >
        <BriefcaseRemoveOutline className={classes.icon} fontSize="small" />
        {t('Requests for takedown')}
      </Button>
      <ArrowForwardIosOutlined
        color="primary"
        classes={{ root: classes.arrow }}
      />
      <Button
        component={Link}
        to={`/dashboard/cases/rfts/${caseId}`}
        variant={
          location.pathname === `/dashboard/cases/rfts/${caseId}`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname === `/dashboard/cases/rfts/${caseId}`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        {t('Overview')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/cases/rfts/${caseId}/knowledge`}
        variant={
          location.pathname.includes(
            `/dashboard/cases/rfts/${caseId}/knowledge`,
          )
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname.includes(
            `/dashboard/cases/rfts/${caseId}/knowledge`,
          )
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        {t('Knowledge')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/cases/rfts/${caseId}/content`}
        variant={
          location.pathname === `/dashboard/cases/rfts/${caseId}/content`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname === `/dashboard/cases/rfts/${caseId}/content`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        {t('Content')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/cases/rfts/${caseId}/entities`}
        variant={
          location.pathname === `/dashboard/cases/rfts/${caseId}/entities`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname === `/dashboard/cases/rfts/${caseId}/entities`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        {t('Entities')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/cases/rfts/${caseId}/observables`}
        variant={
          location.pathname === `/dashboard/cases/rfts/${caseId}/observables`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname === `/dashboard/cases/rfts/${caseId}/observables`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        {t('Observables')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/cases/rfts/${caseId}/files`}
        variant={
          location.pathname === `/dashboard/cases/rfts/${caseId}/files`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname === `/dashboard/cases/rfts/${caseId}/files`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        {t('Data')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/cases/rfts/${caseId}/history`}
        variant={
          location.pathname === `/dashboard/cases/rfts/${caseId}/history`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname === `/dashboard/cases/rfts/${caseId}/history`
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

export default TopMenuCaseRft;
