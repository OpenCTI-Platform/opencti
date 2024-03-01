import React, { FunctionComponent } from 'react';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, PreloadedQuery } from 'react-relay';
import Chip from '@mui/material/Chip';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import { Position_position$data } from './__generated__/Position_position.graphql';
import type { Theme } from '../../../../components/Theme';
import { PositionDetailsLocationRelationshipsLinesQueryLinesPaginationQuery } from './__generated__/PositionDetailsLocationRelationshipsLinesQueryLinesPaginationQuery.graphql';
import usePreloadedFragment from '../../../../utils/hooks/usePreloadedFragment';
import { PositionDetails_positionRelationships$key } from './__generated__/PositionDetails_positionRelationships.graphql';
import { isNotEmptyField } from '../../../../utils/utils';

const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 4,
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    borderRadius: 4,
    color: theme.palette.text?.primary,
    textTransform: 'uppercase',
    margin: '0 5px 5px 0',
  },
}));

interface PositionDetailsProps {
  position: Position_position$data;
  queryRef: PreloadedQuery<PositionDetailsLocationRelationshipsLinesQueryLinesPaginationQuery>;
}

export const positionDetailsLocationRelationshipsLinesQuery = graphql`
  query PositionDetailsLocationRelationshipsLinesQueryLinesPaginationQuery(
    $fromOrToId: [String]!
    $relationship_type: [String]
    $confidences: [Int]
    $orderBy: StixCoreRelationshipsOrdering
    $orderMode: OrderingMode
    $count: Int
    $cursor: ID
  ) {
    ...PositionDetails_positionRelationships
      @arguments(
        fromOrToId: $fromOrToId
        relationship_type: $relationship_type
        confidences: $confidences
        orderBy: $orderBy
        orderMode: $orderMode
        count: $count
        cursor: $cursor
      )
  }
`;

export const positionDetailsRelationshipsFragment = graphql`
  fragment PositionDetails_positionRelationships on Query
  @argumentDefinitions(
    fromOrToId: { type: "[String]!" }
    relationship_type: { type: "[String]" }
    confidences: { type: "[Int]" }
    orderBy: {
      type: "StixCoreRelationshipsOrdering"
      defaultValue: entity_type
    }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
  )
  @refetchable(queryName: "PositionRefetchQuery") {
    stixCoreRelationships(
      fromOrToId: $fromOrToId
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

const PositionDetails: FunctionComponent<PositionDetailsProps> = ({
  position,
  queryRef,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const data = usePreloadedFragment<
  PositionDetailsLocationRelationshipsLinesQueryLinesPaginationQuery,
  PositionDetails_positionRelationships$key
  >({
    queryDef: positionDetailsLocationRelationshipsLinesQuery,
    fragmentDef: positionDetailsRelationshipsFragment,
    queryRef,
  });
  const getTargetedEntities = (type: string) => (data?.stixCoreRelationships?.edges ?? [])
    .filter(({ node }) => isNotEmptyField(node.to))
    .filter(({ node }) => node.to?.entity_type === type)
    .map(({ node }) => node.to?.name);
  const cities = getTargetedEntities('City');
  const countries = getTargetedEntities('Country');
  const regions = getTargetedEntities('Region');
  const areas = getTargetedEntities('Administrative-Area');
  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Description')}
            </Typography>
            {position.description && (
              <ExpandableMarkdown source={position.description} limit={300} />
            )}
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Latitude')}
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
              {t_i18n('Longitude')}
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
              {t_i18n('Street address')}
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
              {t_i18n('Postal code')}
            </Typography>
            {position.postal_code && (
              <ExpandableMarkdown source={position.postal_code} limit={300} />
            )}
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('City')}
            </Typography>
            {cities
              && cities.map((name) => (
                <Chip
                  key={name}
                  classes={{ root: classes.chip }}
                  label={name}
                />
              ))}
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Country')}
            </Typography>
            {countries
              && countries.map((name) => (
                <Chip
                  key={name}
                  classes={{ root: classes.chip }}
                  label={name}
                />
              ))}
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Region')}
            </Typography>
            {regions
              && regions.map((name) => (
                <Chip
                  key={name}
                  classes={{ root: classes.chip }}
                  label={name}
                />
              ))}
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('entity_Administrative-Area')}
            </Typography>
            {areas
              && areas.map((name) => (
                <Chip
                  key={name}
                  classes={{ root: classes.chip }}
                  label={name}
                />
              ))}
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default PositionDetails;
