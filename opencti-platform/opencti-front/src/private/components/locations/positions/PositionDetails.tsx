import React, { FunctionComponent } from 'react';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import { graphql } from 'react-relay';
import Chip from '@mui/material/Chip';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import { Position_position$data } from './__generated__/Position_position.graphql';
import { Theme } from '../../../../components/Theme';
import { QueryRenderer } from '../../../../relay/environment';
import {
  PositionDetailsLocationRelationshipsLinesQueryLinesPaginationQuery$data,
} from './__generated__/PositionDetailsLocationRelationshipsLinesQueryLinesPaginationQuery.graphql';

const positionDetailsLocationRelationshipsLinesQuery = graphql`
    query PositionDetailsLocationRelationshipsLinesQueryLinesPaginationQuery(
        $elementId: [String]!
        $relationship_type: [String]
        $confidences: [Int]
        $orderBy: StixCoreRelationshipsOrdering
        $orderMode: OrderingMode
        $count: Int!
        $cursor: ID
    ) {
        stixCoreRelationships(
            elementId: $elementId
            relationship_type: $relationship_type
            confidences: $confidences
            orderBy: $orderBy
            orderMode: $orderMode
            first: $count
            after: $cursor
        ) @connection(key: "Pagination_stixCoreRelationships") {
            edges {
                node {
                    id
                    entity_type
                    parent_types
                    relationship_type
                    confidence
                    start_time
                    stop_time
                    description
                    is_inferred
                    created_at
                    to {
                      ... on Position {
                          name
                          description
                      }
                      ... on City {
                          id
                          name
                          description
                          entity_type
                      }
                      ... on AdministrativeArea {
                          id
                          name
                          description
                          entity_type
                      }
                      ... on Country {
                          id
                          name
                          description
                          entity_type
                      }
                      ... on Region {
                          id
                          name
                          description
                          entity_type
                      }
                    }
                }
            }
        }
    }
`;

const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    borderRadius: 5,
    color: theme.palette.text?.primary,
    textTransform: 'uppercase',
    margin: '0 5px 5px 0',
  },
}));

interface PositionDetailsProps {
  position: Position_position$data
}

const PositionDetails: FunctionComponent<PositionDetailsProps> = ({ position }) => {
  const { t } = useFormatter();
  const classes = useStyles();

  return (
    <QueryRenderer
      query={
        positionDetailsLocationRelationshipsLinesQuery
      }
      variables={{
        count: 20,
        elementId: [position.id],
        relationship_type: 'located-at',
      }}
      render={({ props }: { props: PositionDetailsLocationRelationshipsLinesQueryLinesPaginationQuery$data }) => {
        const targets = props?.stixCoreRelationships?.edges;
        const cities = targets?.filter((n) => n?.node.to?.entity_type === 'City').map((n) => n?.node.to?.name);
        const countries = targets?.filter((n) => n?.node.to?.entity_type === 'Country').map((n) => n?.node.to?.name);
        const regions = targets?.filter((n) => n?.node.to?.entity_type === 'Region').map((n) => n?.node.to?.name);
        const areas = targets?.filter((n) => n?.node.to?.entity_type === 'Administrative-Area').map((n) => n?.node.to?.name);
        return (
            <div style={{ height: '100%' }}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Details')}
              </Typography>
              <Paper classes={{ root: classes.paper }} variant="outlined">
                <Grid container={true} spacing={3}>
                  <Grid item={true} xs={12}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Description')}
                    </Typography>
                    {position.description && (
                      <ExpandableMarkdown
                        source={position.description}
                        limit={300}
                      />
                    )}
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Latitude')}
                    </Typography>
                    {position.latitude && (
                      <ExpandableMarkdown
                        source={position.latitude.toString()}
                        limit={300}
                      />
                    )}
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Longitude')}
                    </Typography>
                    {position.longitude && (
                      <ExpandableMarkdown
                        source={position.longitude.toString()}
                        limit={300}
                      />
                    )}
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Street address')}
                    </Typography>
                    {position.street_address && (
                      <ExpandableMarkdown
                        source={position.street_address}
                        limit={300}
                      />
                    )}
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Postal code')}
                    </Typography>
                    {position.postal_code && (
                      <ExpandableMarkdown
                        source={position.postal_code}
                        limit={300}
                      />
                    )}
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('City')}
                    </Typography>
                    {cities && cities.map((name) => <Chip
                      key={name}
                      classes={{ root: classes.chip }}
                      label={name}
                    />)}
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Country')}
                    </Typography>
                    {countries && countries.map((name) => <Chip
                      key={name}
                      classes={{ root: classes.chip }}
                      label={name}
                    />)}
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Region')}
                    </Typography>
                    {regions && regions.map((name) => <Chip
                      key={name}
                      classes={{ root: classes.chip }}
                      label={name}
                    />)}
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('entity_Administrative-Area')}
                    </Typography>
                    {areas && areas.map((name) => <Chip
                      key={name}
                      classes={{ root: classes.chip }}
                      label={name}
                    />)}
                  </Grid>
                </Grid>
              </Paper>
            </div>
        );
      }}
    />
  );
};

export default PositionDetails;
