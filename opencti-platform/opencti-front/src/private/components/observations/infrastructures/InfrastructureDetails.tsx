import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Chip from '@mui/material/Chip';
import { List } from '@mui/material';
import makeStyles from '@mui/styles/makeStyles';
import EntityStixCoreRelationshipsDonut from '../../common/stix_core_relationships/EntityStixCoreRelationshipsDonut';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import StixCoreObjectKillChainPhasesView from '../../common/stix_core_objects/StixCoreObjectKillChainPhasesView';
import { Theme } from '../../../../components/Theme';
import {
  InfrastructureDetails_infrastructure$data,
  InfrastructureDetails_infrastructure$key,
} from './__generated__/InfrastructureDetails_infrastructure.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  item: {
    paddingLeft: 10,
    transition: 'background-color 0.1s ease',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text?.primary,
    textTransform: 'uppercase',
    borderRadius: '0',
    margin: '0 5px 5px 0',
  },
}));

const InfrastructureDetailsFragment = graphql`
  fragment InfrastructureDetails_infrastructure on Infrastructure {
    id
    name
    description
    infrastructure_types
    first_seen
    last_seen
    killChainPhases {
      edges {
        node {
          id
          entity_type
          kill_chain_name
          phase_name
          x_opencti_order
        }
      }
    }
    objectLabel {
      edges {
        node {
          id
          value
          color
        }
      }
    }
  }
`;

interface InfrastructureDetailsProps {
  infrastructure: InfrastructureDetails_infrastructure$key;
}

const InfrastructureDetails: FunctionComponent<InfrastructureDetailsProps> = ({
  infrastructure,
}) => {
  const classes = useStyles();
  const { t, fldt } = useFormatter();

  const data: InfrastructureDetails_infrastructure$data = useFragment(
    InfrastructureDetailsFragment,
    infrastructure,
  );
  const killChainPhases = data?.killChainPhases?.edges ?? data?.killChainPhases?.edges ?? [];

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Infrastructure types')}
            </Typography>
            {data.infrastructure_types && data.infrastructure_types.length > 0
              ? <List>{
                data.infrastructure_types.map(
                  (infrastructureType) => (
                    <Chip
                      key={infrastructureType}
                      classes={{ root: classes.chip }}
                      label={infrastructureType}
                    />
                  ),
                )
              }
              </List>
              : ('-')}
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Description')}
            </Typography>
            <ExpandableMarkdown
              source={data.description}
              limit={400}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('First seen')}
            </Typography>
            {data.first_seen ? fldt(data.first_seen) : ('-')}
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Last seen')}
            </Typography>
            {data.last_seen ? fldt(data.last_seen) : ('-')}
          </Grid>
          <Grid item={true} xs={6}>
            <StixCoreObjectKillChainPhasesView killChainPhasesEdges={killChainPhases} />
          </Grid>
        </Grid>
        <br />
        <EntityStixCoreRelationshipsDonut
          variant="inEntity"
          fromId={data.id}
          toTypes={['Stix-Cyber-Observable']}
          relationshipType="consists-of"
          field="entity_type"
          height={260}
          isTo={true}
        />
      </Paper>
    </div>
  );
};

export default InfrastructureDetails;
