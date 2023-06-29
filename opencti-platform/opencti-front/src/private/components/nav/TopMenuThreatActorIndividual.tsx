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

const TopMenuThreatActorIndividual = () => {
  const classes = useStyles();
  const location = useLocation();
  const { t } = useFormatter();
  const { threatActorIndividualId } = useParams();
  return (
    <div>
      <Button
        component={Link}
        to="/dashboard/threats/threat_actors_individual"
        variant="contained"
        size="small"
        color="primary"
        classes={{ root: classes.buttonHome }}
      >
        <LaptopAccount className={classes.icon} fontSize="small" />
        {t('Threat actors individual')}
      </Button>
      <ArrowForwardIosOutlined
        color="primary"
        classes={{ root: classes.arrow }}
      />
      <Button
        component={Link}
        to={`/dashboard/threats/threat_actors_individual/${threatActorIndividualId}`}
        variant={
          location.pathname
          === `/dashboard/threats/threat_actors_individual/${threatActorIndividualId}`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname
          === `/dashboard/threats/threat_actors_individual/${threatActorIndividualId}`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        {t('Overview')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/threats/threat_actors_individual/${threatActorIndividualId}/knowledge`}
        variant={
          location.pathname.includes(
            `/dashboard/threats/threat_actors_individual/${threatActorIndividualId}/knowledge`,
          )
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname.includes(
            `/dashboard/threats/threat_actors_individual/${threatActorIndividualId}/knowledge`,
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
        to={`/dashboard/threats/threat_actors_individual/${threatActorIndividualId}/analysis`}
        variant={
          location.pathname
          === `/dashboard/threats/threat_actors_individual/${threatActorIndividualId}/analysis`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname
          === `/dashboard/threats/threat_actors_individual/${threatActorIndividualId}/analysis`
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        {t('Analysis')}
      </Button>
      <Button
        component={Link}
        to={`/dashboard/threats/threat_actors_individual/${threatActorIndividualId}/indicators`}
        variant={
          location.pathname.includes(
            `/dashboard/threats/threat_actors_individual/${threatActorIndividualId}/indicators`,
          )
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname.includes(
            `/dashboard/threats/threat_actors_individual/${threatActorIndividualId}/indicators`,
          )
            ? 'secondary'
            : 'primary'
        }
        classes={{ root: classes.button }}
      >
        {t('Indicators')}
      </Button>
      <Security needs={[KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT]}>
        <Button
          component={Link}
          to={`/dashboard/threats/threat_actors_individual/${threatActorIndividualId}/files`}
          variant={
            location.pathname
            === `/dashboard/threats/threat_actors_individual/${threatActorIndividualId}/files`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/threats/threat_actors_individual/${threatActorIndividualId}/files`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('Data')}
        </Button>
      </Security>
      <Button
        component={Link}
        to={`/dashboard/threats/threat_actors_individual/${threatActorIndividualId}/history`}
        variant={
          location.pathname
          === `/dashboard/threats/threat_actors_individual/${threatActorIndividualId}/history`
            ? 'contained'
            : 'text'
        }
        size="small"
        color={
          location.pathname
          === `/dashboard/threats/threat_actors_individual/${threatActorIndividualId}/history`
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

export default TopMenuThreatActorIndividual;
