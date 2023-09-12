import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@mui/material/Button';
import { ArrowForwardIosOutlined, StreamOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../components/i18n';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNGETEXPORT, KNOWLEDGE_KNUPLOAD } from '../../../utils/hooks/useGranted';
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

const TopMenuDataSource = ({ id: dataSourceId }: { id: string }) => {
  const location = useLocation();
  const { t } = useFormatter();
  const classes = styles();
  return (
    <div>
      <Button
        component={Link}
        to="/dashboard/techniques/data_sources"
        variant="contained"
        size="small"
        color="primary"
        classes={{ root: classes.buttonHome }}
      >
        <StreamOutlined className={classes.icon} fontSize="small" />
        {t('Data sources')}
      </Button>
      <ArrowForwardIosOutlined
        color="primary"
        classes={{ root: classes.arrow }}
      />
      <Button
        component={Link}
        to={`/dashboard/techniques/data_sources/${dataSourceId}`}
        variant={
          location.pathname
          === `/dashboard/techniques/data_sources/${dataSourceId}`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname
          === `/dashboard/techniques/data_sources/${dataSourceId}`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!dataSourceId}
      >
        {t('Overview')}
      </Button>
      <Security needs={[KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT]}>
        <Button
          component={Link}
          to={`/dashboard/techniques/data_sources/${dataSourceId}/files`}
          variant={
            location.pathname
            === `/dashboard/techniques/data_sources/${dataSourceId}/files`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/techniques/data_sources/${dataSourceId}/files`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!dataSourceId}
        >
          {t('Data')}
        </Button>
      </Security>
      <Button
        component={Link}
        to={`/dashboard/techniques/data_sources/${dataSourceId}/history`}
        variant={
          location.pathname
          === `/dashboard/techniques/data_sources/${dataSourceId}/history`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname
          === `/dashboard/techniques/data_sources/${dataSourceId}/history`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!dataSourceId}
      >
        {t('History')}
      </Button>
    </div>
  );
};

export default TopMenuDataSource;
