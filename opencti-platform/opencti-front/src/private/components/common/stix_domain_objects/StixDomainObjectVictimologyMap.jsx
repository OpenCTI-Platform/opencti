import React, { Suspense } from 'react';
import { Typography, Paper } from '@mui/material';
import { graphql, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import LocationMiniMapTargets from '../location/LocationMiniMapTargets';
import { computeLevel } from '../../../../utils/Number';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const stixDomainObjectVictimologyMapQuery = graphql`
  query StixDomainObjectVictimologyMapQuery(
    $fromId: [String]
    $field: String!
    $operation: StatsOperation!
    $relationship_type: [String]
    $toTypes: [String]
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $limit: Int
    $isTo: Boolean
  ) {
    stixCoreRelationshipsDistribution(
      fromId: $fromId
      field: $field
      operation: $operation
      relationship_type: $relationship_type
      toTypes: $toTypes
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      limit: $limit
      isTo: $isTo
    ) {
      label
      value
      entity {
        ... on BasicObject {
          entity_type
        }
        ... on BasicRelationship {
          entity_type
        }
        ... on Country {
          name
          x_opencti_aliases
          latitude
          longitude
        }
      }
    }
  }
`;

const VictimologyMap = ({ queryRef }) => {
  const { stixCoreRelationshipsDistribution } = usePreloadedQuery(
    stixDomainObjectVictimologyMapQuery,
    queryRef,
  );

  const values = stixCoreRelationshipsDistribution.map((d) => d.value);
  const countries = stixCoreRelationshipsDistribution.map((d) => {
    const lastValue = values[values.length - 1];
    const headValue = values[0];
    return {
      ...d.entity,
      level: computeLevel(d.value, lastValue, headValue + 1),
    };
  });

  return (
    <LocationMiniMapTargets
      center={[48.8566969, 2.3514616]}
      countries={countries}
      zoom={2}
    />
  );
};

const StixDomainObjectVictimologyMap = ({
  title,
  variant,
  stixDomainObjectId,
  startDate,
  endDate,
  timeField,
}) => {
  const { t_i18n } = useFormatter();
  const queryRef = useQueryLoading(
    stixDomainObjectVictimologyMapQuery,
    {
      fromId: stixDomainObjectId,
      field: 'internal_id',
      operation: 'count',
      relationship_type: 'targets',
      toTypes: ['Country'],
      startDate,
      endDate,
      dateAttribute: timeField === 'functional' ? 'start_time' : 'created_at',
      limit: 20,
      isTo: true,
    },
  );

  if (!queryRef) {
    return null;
  }

  return (
    <div style={{ height: '100%', paddingBottom: variant !== 'inLine' ? 0 : 10 }}>
      <Typography
        gutterBottom={true}
        variant={variant === 'inEntity' ? 'h3' : 'h4'}
        style={{ margin: variant !== 'inLine' ? '0 0 10px 0' : '-10px 0 10px -7px' }}
      >
        {title || t_i18n('Victimology map')}
      </Typography>
      {variant === 'inLine' || variant === 'inEntity' ? (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <VictimologyMap queryRef={queryRef} />
        </Suspense>
      ) : (
        <Paper
          variant="outlined"
          sx={{
            height: '100%',
            margin: '4px 0 0 0',
            borderRadius: 1,
          }}
        >
          <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <VictimologyMap queryRef={queryRef} />
          </Suspense>
        </Paper>
      )}
    </div>
  );
};

export default StixDomainObjectVictimologyMap;
