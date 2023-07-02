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

const useStyles = makeStyles((theme) => ({
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

const TopMenuThreatActor = () => {
  const classes = useStyles();
  const location = useLocation();
  const { t } = useFormatter();
  const { threatActorId } = useParams();
  return (
    <div>
      <Button
        component={Link}
        to="/dashboard/threats/threat_actors"
        variant="contained"
        size="small"
        color="primary"
        classes={{ root: classes.buttonHome }}
      >
        <LaptopAccount className={classes.icon} fontSize="small" />
        {t('Threat actors')}
      </Button>
      <ArrowForwardIosOutlined
        color="primary"
        classes={{ root: classes.arrow }}
      />
      <Button
        component={Link}
        to={`/dashboard/threats/threat_actors/${threatActorId}`}
        variant={
          location.pathname
          === `/dashboard/threats/threat_actors/${threatActorId}`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname
          === `/dashboard/threats/threat_actors/${threatActorId}`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!threatActorId}
      >
        {t('Overview')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/threats/threat_actors/${threatActorId}/knowledge`}
        variant={
          location.pathname.includes(
            `/dashboard/threats/threat_actors/${threatActorId}/knowledge`,
          )
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname.includes(
            `/dashboard/threats/threat_actors/${threatActorId}/knowledge`,
          )
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!threatActorId}
      >
        {t('Knowledge')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/threats/threat_actors/${threatActorId}/analysis`}
        variant={
          location.pathname
          === `/dashboard/threats/threat_actors/${threatActorId}/analysis`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname
          === `/dashboard/threats/threat_actors/${threatActorId}/analysis`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!threatActorId}
      >
        {t('Analysis')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/threats/threat_actors/${threatActorId}/indicators`}
        variant={
          location.pathname.includes(
            `/dashboard/threats/threat_actors/${threatActorId}/indicators`,
          )
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname.includes(
            `/dashboard/threats/threat_actors/${threatActorId}/indicators`,
          )
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!threatActorId}
      >
        {t('Indicators')}
      </Button>
      <Security needs={[KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT]}>
        <Button
          component={Link}
          to={`/dashboard/threats/threat_actors/${threatActorId}/files`}
          variant={
            location.pathname
            === `/dashboard/threats/threat_actors/${threatActorId}/files`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/threats/threat_actors/${threatActorId}/files`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!threatActorId}
        >
          {t('Data')}
        </Button>
      </Security>
      <Button
        component={Link}
        to={`/dashboard/threats/threat_actors/${threatActorId}/history`}
        variant={
          location.pathname
          === `/dashboard/threats/threat_actors/${threatActorId}/history`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname
          === `/dashboard/threats/threat_actors/${threatActorId}/history`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
        disabled={!threatActorId}
      >
        {t('History')}
      </Button>
    </div>
  );
};

export default TopMenuThreatActor;
