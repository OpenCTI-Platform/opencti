import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import {
  BiotechOutlined,
  DescriptionOutlined,
  LocalOfferOutlined,
  SubjectOutlined,
  WorkspacesOutlined,
} from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
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

const TopMenuAnalyses = () => {
  const classes = useStyles();
  const location = useLocation();
  const { t } = useFormatter();
  return (
    <div>
      {!useIsHiddenEntity('Report') && (
        <Button
          component={Link}
          to="/dashboard/analyses/reports"
          variant={
            location.pathname === '/dashboard/analyses/reports'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/analyses/reports'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <DescriptionOutlined className={classes.icon} fontSize="small" />
          {t('Reports')}
        </Button>
      )}
      {!useIsHiddenEntity('Grouping') && (
        <Button
          component={Link}
          to="/dashboard/analyses/groupings"
          variant={
            location.pathname === '/dashboard/analyses/groupings'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/analyses/groupings'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <WorkspacesOutlined className={classes.icon} fontSize="small" />
          {t('Groupings')}
        </Button>
      )}
      {!useIsHiddenEntity('Malware-Analysis') && (
        <Button
          component={Link}
          to="/dashboard/analyses/malware_analyses"
          variant={
            location.pathname === '/dashboard/analyses/malware_analyses'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/analyses/malware_analyses'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <BiotechOutlined className={classes.icon} fontSize="small" />
          {t('Malware Analyses')}
        </Button>
      )}
      {!useIsHiddenEntity('Note') && (
        <Button
          component={Link}
          to="/dashboard/analyses/notes"
          variant={
            location.pathname === '/dashboard/analyses/notes'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/analyses/notes'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <SubjectOutlined className={classes.icon} fontSize="small" />
          {t('Notes')}
        </Button>
      )}
      <Button
        component={Link}
        to="/dashboard/analyses/external_references"
        variant={
          location.pathname === '/dashboard/analyses/external_references'
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname === '/dashboard/analyses/external_references'
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

export default TopMenuAnalyses;
