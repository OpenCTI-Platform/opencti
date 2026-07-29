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
import { ContainerCorrelationTimelineQuery } from './__generated__/ContainerCorrelationTimelineQuery.graphql';

// Same idea as the entity view, but the left column comes from the objects the
// container already holds instead of from its relationships.
const containerCorrelationTimelineQuery = graphql`
  query ContainerCorrelationTimelineQuery(
    $id: String!
    $count: Int!
    $containersCount: Int!
    $containerTypes: [String!]
    $relationshipsCount: Int!
    $entityFilters: FilterGroup
  ) {
    container(id: $id) {
      id
      objects(first: $count) {
        edges {
          node {
            ... on BasicObject {
              id
              entity_type
              parent_types
            }
            ... on StixCoreObject {
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
    }
  }
`;

const OBJECTS_COUNT = 200;
const CONTAINERS_PER_OBJECT = 50;
const RELATIONSHIPS_PER_OBJECT = 50;

interface ContainerCorrelationTimelineProps {
  containerId: string;
}

const ContainerCorrelationTimelineComponent = ({
  containerId,
}: ContainerCorrelationTimelineProps) => {
  const { t_i18n } = useFormatter();
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
      id: containerId,
      count: OBJECTS_COUNT,
      containersCount: CONTAINERS_PER_OBJECT,
      containerTypes: CORRELATION_CONTAINER_TYPES,
      relationshipsCount: RELATIONSHIPS_PER_OBJECT,
      entityFilters: {
        mode: 'and' as const,
        filters: [{ key: ['elementWithTargetTypes'], values: CORRELATION_ENTITY_TYPES }],
        filterGroups: [],
      },
    }),
    [containerId],
  );

  // Everything is fetched once and filtered client-side, so toggling target
  // types or the date reference never triggers a refetch.
  const data = useLazyLoadQuery<ContainerCorrelationTimelineQuery>(
    containerCorrelationTimelineQuery,
    variables,
  );

  const objects = useMemo<RawCorrelationObject[]>(() => {
    const result: RawCorrelationObject[] = [];
    (data.container?.objects?.edges ?? []).forEach((edge) => {
      const node = edge?.node;
      // `objects` also carries relationships, which hold nothing to correlate
      // on: only keep the addressable core objects.
      if (!node?.id || !node.entity_type || !node.representative) return;
      const objectId = node.id;
      const containers: RawCorrelationTarget[] = (node.containers?.edges ?? []).map(
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
      const entities: RawCorrelationTarget[] = (node.stixCoreRelationships?.edges ?? [])
        .map((relationEdge) => pickRelatedTarget(
          objectId,
          relationEdge.node.from,
          relationEdge.node.to,
        ))
        .filter((target): target is RawCorrelationTarget => target !== null);
      result.push({
        id: objectId,
        entityType: node.entity_type,
        parentTypes: node.parent_types ?? [],
        label: node.representative.main,
        containersTotal: node.containersNumber?.total ?? 0,
        targets: [...containers, ...entities],
      });
    });
    return result;
  }, [data]);

  const availableSourceTypes = useMemo(() => listSourceTypes(objects), [objects]);

  const { sources, targets, overCorrelated } = useMemo(
    () => buildCorrelationModel(objects, {
      maxContainers,
      minShared,
      sourceTypes,
      targetTypes,
      dateReference,
      // The container being viewed holds every source, so it would correlate
      // with itself on every single row.
      excludeIds: [containerId],
    }),
    [objects, maxContainers, minShared, sourceTypes, targetTypes, dateReference, containerId],
  );

  return (
    // The toolbar is a permanent bottom drawer floating over the page, so the
    // last rows of the chart need room to breathe underneath.
    <Box sx={{ marginTop: 2, paddingBottom: `${TOOLBAR_HEIGHT + 16}px` }}>
      <CorrelationTimelineGraph
        sources={sources}
        targets={targets}
        sourcesLabel={t_i18n('Objects of this container')}
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

const ContainerCorrelationTimeline = ({ containerId }: ContainerCorrelationTimelineProps) => (
  <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
    <ContainerCorrelationTimelineComponent containerId={containerId} />
  </Suspense>
);

export default ContainerCorrelationTimeline;
