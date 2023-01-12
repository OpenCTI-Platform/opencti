import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import {
  DescriptionOutlined,
  LocalOfferOutlined,
  ReviewsOutlined,
  SubjectOutlined,
  WorkspacesOutlined,
} from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
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

const TopMenuAnalysis = () => {
  const classes = useStyles();
  const location = useLocation();
  const { t } = useFormatter();

  return (
      <div>
        <Button
          component={Link}
          to="/dashboard/analysis/reports"
          variant={
            location.pathname === '/dashboard/analysis/reports'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/analysis/reports'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <DescriptionOutlined className={classes.icon} fontSize="small" />
          {t('Reports')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/analysis/groupings"
          variant={
            location.pathname === '/dashboard/analysis/groupings'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/analysis/groupings'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <WorkspacesOutlined className={classes.icon} fontSize="small" />
          {t('Groupings')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/analysis/notes"
          variant={
            location.pathname === '/dashboard/analysis/notes'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/analysis/notes'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <SubjectOutlined className={classes.icon} fontSize="small" />
          {t('Notes')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/analysis/opinions"
          variant={
            location.pathname === '/dashboard/analysis/opinions'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/analysis/opinions'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <ReviewsOutlined className={classes.icon} fontSize="small" />
          {t('Opinions')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/analysis/external_references"
          variant={
            location.pathname === '/dashboard/analysis/external_references'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/analysis/external_references'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <LocalOfferOutlined className={classes.icon} fontSize="small" />
          {t('External references')}
        </Button>
      </div>
  );
};

export default TopMenuAnalysis;
