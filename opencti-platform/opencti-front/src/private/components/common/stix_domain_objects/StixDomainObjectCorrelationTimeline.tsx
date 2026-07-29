import { Suspense, useMemo, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Box from '@mui/material/Box';
import CorrelationTimelineGraph from '../../../../components/correlation_timeline/CorrelationTimelineGraph';
import CorrelationTimelineToolbar, { TOOLBAR_HEIGHT } from '../../../../components/correlation_timeline/CorrelationTimelineToolbar';
import {
  buildCorrelationModel,
  CORRELATION_CONTAINER_TYPES,
  CORRELATION_ENTITY_TYPES,
  CORRELATION_TARGET_TYPES,
  DateReference,
  listSourceTypes,
  pickRelatedTarget,
  RawCorrelationObject,
  RawCorrelationTarget,
} from '../../../../components/correlation_timeline/correlationTimelineModel';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { StixDomainObjectCorrelationTimelineQuery } from './__generated__/StixDomainObjectCorrelationTimelineQuery.graphql';

// Entity-agnostic: `regardingOf` resolves the objects related to any STIX
// domain object, so the same query serves Incidents, Campaigns, Intrusion Sets
// and the rest. One single round trip brings the related objects and, for each,
// the containers of the platform holding it. `containersNumber` gives the
// correlation degree without fetching every container, which is what makes the
// over-correlation filter cheap.
const stixDomainObjectCorrelationTimelineQuery = graphql`
  query StixDomainObjectCorrelationTimelineQuery(
    $filters: FilterGroup
    $count: Int!
    $containersCount: Int!
    $containerTypes: [String!]
    $relationshipsCount: Int!
    $entityFilters: FilterGroup
  ) {
    stixCoreObjects(first: $count, filters: $filters) {
      edges {
        node {
          id
          entity_type
          parent_types
          representative {
            main
          }
          containersNumber {
            total
          }
          containers(first: $containersCount, entityTypes: $containerTypes) {
            edges {
              node {
                id
                entity_type
                created
                created_at
                representative {
                  main
                }
                ... on Report {
                  published
                }
              }
            }
          }
          # Campaigns and incidents are not containers: they are reached
          # through core relationships, in either direction.
          stixCoreRelationships(first: $relationshipsCount, filters: $entityFilters) {
            edges {
              node {
                id
                from {
                  ... on BasicObject {
                    id
                    entity_type
                  }
                  ... on StixCoreObject {
                    created_at
                    representative {
                      main
                    }
                  }
                  ... on StixDomainObject {
                    created
                  }
                  ... on Campaign {
                    first_seen
                  }
                  ... on Incident {
                    first_seen
                  }
                }
                to {
                  ... on BasicObject {
                    id
                    entity_type
                  }
                  ... on StixCoreObject {
                    created_at
                    representative {
                      main
                    }
                  }
                  ... on StixDomainObject {
                    created
                  }
                  ... on Campaign {
                    first_seen
                  }
                  ... on Incident {
                    first_seen
                  }
                }
              }
            }
          }
        }
      }
    }
  }
`;

const OBJECTS_COUNT = 200;
const CONTAINERS_PER_OBJECT = 50;
const RELATIONSHIPS_PER_OBJECT = 50;

interface StixDomainObjectCorrelationTimelineProps {
  stixDomainObjectId: string;
}

const StixDomainObjectCorrelationTimelineComponent = ({
  stixDomainObjectId,
}: StixDomainObjectCorrelationTimelineProps) => {
  const { t_i18n } = useFormatter();
  // Over-correlating objects (8.8.8.8, google.com, a system DLL hash...) are
  // hidden by default: they correlate with everything and turn the view into
  // noise.
  const [maxContainers, setMaxContainers] = useState<number>(20);
  const [minShared, setMinShared] = useState<number>(1);
  // null means "every type present in the data".
  const [sourceTypes, setSourceTypes] = useState<string[] | null>(null);
  const [targetTypes, setTargetTypes] = useState<string[]>(CORRELATION_TARGET_TYPES);
  const [dateReference, setDateReference] = useState<DateReference>('functional');

  // Memoized: a fresh variables object on every render makes Relay rebuild the
  // operation, which re-suspends the tree and makes the whole view blink.
  const variables = useMemo(
    () => ({
      count: OBJECTS_COUNT,
      containersCount: CONTAINERS_PER_OBJECT,
      containerTypes: CORRELATION_CONTAINER_TYPES,
      relationshipsCount: RELATIONSHIPS_PER_OBJECT,
      filters: {
        mode: 'and' as const,
        filters: [{ key: ['regardingOf'], values: [{ key: 'id', values: [stixDomainObjectId] }] }],
        filterGroups: [],
      },
      entityFilters: {
        mode: 'and' as const,
        filters: [{ key: ['elementWithTargetTypes'], values: CORRELATION_ENTITY_TYPES }],
        filterGroups: [],
      },
    }),
    [stixDomainObjectId],
  );

  // Everything is fetched once and filtered client-side, so toggling target
  // types or the date reference never triggers a refetch.
  const data = useLazyLoadQuery<StixDomainObjectCorrelationTimelineQuery>(
    stixDomainObjectCorrelationTimelineQuery,
    variables,
  );

  const objects = useMemo<RawCorrelationObject[]>(
    () => (data.stixCoreObjects?.edges ?? []).map((edge) => {
      const containers: RawCorrelationTarget[] = (edge.node.containers?.edges ?? []).map(
        (containerEdge) => ({
          id: containerEdge.node.id,
          entityType: containerEdge.node.entity_type,
          label: containerEdge.node.representative.main,
          // Reports carry a publication date; other containers fall back on
          // the STIX created date.
          date: containerEdge.node.published ?? containerEdge.node.created ?? null,
          technicalDate: containerEdge.node.created_at ?? null,
        }),
      );
      const entities: RawCorrelationTarget[] = (edge.node.stixCoreRelationships?.edges ?? [])
        .map((relationEdge) => pickRelatedTarget(
          edge.node.id,
          relationEdge.node.from,
          relationEdge.node.to,
        ))
        .filter((target): target is RawCorrelationTarget => target !== null);
      return {
        id: edge.node.id,
        entityType: edge.node.entity_type,
        parentTypes: edge.node.parent_types,
        label: edge.node.representative.main,
        containersTotal: edge.node.containersNumber?.total ?? 0,
        targets: [...containers, ...entities],
      };
    }),
    [data],
  );

  const availableSourceTypes = useMemo(() => listSourceTypes(objects), [objects]);

  const { sources, targets, overCorrelated } = useMemo(
    () => buildCorrelationModel(objects, {
      maxContainers,
      minShared,
      sourceTypes,
      targetTypes,
      dateReference,
      excludeIds: [stixDomainObjectId],
    }),
    [objects, maxContainers, minShared, sourceTypes, targetTypes, dateReference, stixDomainObjectId],
  );

  return (
    // The toolbar is a permanent bottom drawer floating over the page, so the
    // last rows of the chart need room to breathe underneath.
    <Box sx={{ marginTop: 2, paddingBottom: `${TOOLBAR_HEIGHT + 16}px` }}>
      <CorrelationTimelineGraph
        sources={sources}
        targets={targets}
        sourcesLabel={t_i18n('Related objects')}
      />
      <CorrelationTimelineToolbar
        maxContainers={maxContainers}
        setMaxContainers={setMaxContainers}
        minShared={minShared}
        setMinShared={setMinShared}
        targetTypes={targetTypes}
        setTargetTypes={setTargetTypes}
        dateReference={dateReference}
        setDateReference={setDateReference}
        availableSourceTypes={availableSourceTypes}
        sourceTypes={sourceTypes}
        setSourceTypes={setSourceTypes}
        overCorrelated={overCorrelated}
        sourcesCount={sources.length}
        targetsCount={targets.length}
      />
    </Box>
  );
};

const StixDomainObjectCorrelationTimeline = ({
  stixDomainObjectId,
}: StixDomainObjectCorrelationTimelineProps) => (
  <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
    <StixDomainObjectCorrelationTimelineComponent stixDomainObjectId={stixDomainObjectId} />
  </Suspense>
);

export default StixDomainObjectCorrelationTimeline;
