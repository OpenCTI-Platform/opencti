import React, { FunctionComponent } from 'react';
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
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    borderRadius: 4,
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
    $count: Int!
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
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={2}>
          <Grid item xs={12}>
            <Label>
              {t_i18n('Description')}
            </Label>
            <ExpandableMarkdown source={position.description} limit={300} />
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Latitude')}
            </Label>
            <FieldOrEmpty source={position.latitude}>
              <ExpandableMarkdown
                source={position.latitude?.toString()}
                limit={300}
              />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Longitude')}
            </Label>
            <FieldOrEmpty source={position.longitude}>
              <ExpandableMarkdown
                source={position.longitude?.toString()}
                limit={300}
              />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Street address')}
            </Label>
            <FieldOrEmpty source={position.street_address}>
              <ExpandableMarkdown
                source={position.street_address}
                limit={300}
              />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Postal code')}
            </Label>
            <FieldOrEmpty source={position.postal_code}>
              <ExpandableMarkdown source={position.postal_code} limit={300} />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('City')}
            </Label>
            <FieldOrEmpty source={cities}>
              {cities?.map((name) => (
                <Chip
                  key={name}
                  classes={{ root: classes.chip }}
                  label={name}
                />
              ))}
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Country')}
            </Label>
            <FieldOrEmpty source={countries}>
              {countries?.map((name) => (
                <Chip
                  key={name}
                  classes={{ root: classes.chip }}
                  label={name}
                />
              ))}
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Region')}
            </Label>
            <FieldOrEmpty source={regions}>
              {regions?.map((name) => (
                <Chip
                  key={name}
                  classes={{ root: classes.chip }}
                  label={name}
                />
              ))}
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('entity_Administrative-Area')}
            </Label>
            <FieldOrEmpty source={areas}>
              {areas?.map((name) => (
                <Chip
                  key={name}
                  classes={{ root: classes.chip }}
                  label={name}
                />
              ))}
            </FieldOrEmpty>
          </Grid>
        </Grid>
      </Card>
    </div>
  );
};

export default PositionDetails;
