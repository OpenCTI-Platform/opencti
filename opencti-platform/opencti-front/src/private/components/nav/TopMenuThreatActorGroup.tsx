import React from 'react';
import { Link, useLocation, useParams } from 'react-router-dom';
import Button from '@mui/material/Button';
import { ArrowForwardIosOutlined } from '@mui/icons-material';
import { LaptopAccount } from 'mdi-material-ui';
import { makeStyles } from '@mui/styles';
import { useFormatter } from '../../../components/i18n';
import Security from '../../../utils/Security';
import {
  KNOWLEDGE_KNGETEXPORT,
  KNOWLEDGE_KNUPLOAD,
} from '../../../utils/hooks/useGranted';
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

const TopMenuThreatActorGroup = () => {
  const classes = useStyles();
  const location = useLocation();
  const { t } = useFormatter();
  const { threatActorGroupId } = useParams();
  return (
    <div>
      <Button
        component={Link}
        to="/dashboard/threats/threat_actors_group"
        variant="contained"
        size="small"
        color="primary"
        classes={{ root: classes.buttonHome }}
      >
        <LaptopAccount className={classes.icon} fontSize="small" />
        {t('Threat actors group')}
      </Button>
      <ArrowForwardIosOutlined
        color="primary"
        classes={{ root: classes.arrow }}
      />
      <Button
        component={Link}
        to={`/dashboard/threats/threat_actors_group/${threatActorGroupId}`}
        variant={
          location.pathname
          === `/dashboard/threats/threat_actors_group/${threatActorGroupId}`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname
          === `/dashboard/threats/threat_actors_group/${threatActorGroupId}`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!threatActorGroupId}
      >
        {t('Overview')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/threats/threat_actors_group/${threatActorGroupId}/knowledge`}
        variant={
          location.pathname.includes(
            `/dashboard/threats/threat_actors_group/${threatActorGroupId}/knowledge`,
          )
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname.includes(
            `/dashboard/threats/threat_actors_group/${threatActorGroupId}/knowledge`,
          )
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!threatActorGroupId}
      >
        {t('Knowledge')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/threats/threat_actors_group/${threatActorGroupId}/analysis`}
        variant={
          location.pathname
          === `/dashboard/threats/threat_actors_group/${threatActorGroupId}/analysis`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname
          === `/dashboard/threats/threat_actors_group/${threatActorGroupId}/analysis`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!threatActorGroupId}
      >
        {t('Analysis')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/threats/threat_actors_group/${threatActorGroupId}/indicators`}
        variant={
          location.pathname.includes(
            `/dashboard/threats/threat_actors_group/${threatActorGroupId}/indicators`,
          )
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname.includes(
            `/dashboard/threats/threat_actors_group/${threatActorGroupId}/indicators`,
          )
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!threatActorGroupId}
      >
        {t('Indicators')}
      </Button>
      <Security needs={[KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT]}>
        <Button
          component={Link}
          to={`/dashboard/threats/threat_actors_group/${threatActorGroupId}/files`}
          variant={
            location.pathname
            === `/dashboard/threats/threat_actors_group/${threatActorGroupId}/files`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/threats/threat_actors_group/${threatActorGroupId}/files`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!threatActorGroupId}
        >
          {t('Data')}
        </Button>
      </Security>
      <Button
        component={Link}
        to={`/dashboard/threats/threat_actors_group/${threatActorGroupId}/history`}
        variant={
          location.pathname
          === `/dashboard/threats/threat_actors_group/${threatActorGroupId}/history`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname
          === `/dashboard/threats/threat_actors_group/${threatActorGroupId}/history`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!threatActorGroupId}
      >
        {t('History')}
      </Button>
    </div>
  );
};

export default TopMenuThreatActorGroup;
