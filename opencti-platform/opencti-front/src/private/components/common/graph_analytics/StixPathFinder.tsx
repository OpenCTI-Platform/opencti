import React, { ReactNode, useEffect, useId, useMemo, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import { Link } from 'react-router';
import {
  Alert,
  Checkbox,
  Chip,
  Combobox,
  ComboboxChips,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxHelperText,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
  Select,
  SelectContent,
  SelectHelperText,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
  Switch,
  Text,
} from '@filigran/design-system';
import { Box } from '@mui/material';
import { EastOutlined, WestOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import ItemIcon from '../../../../components/ItemIcon';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';
import { fetchQuery, handleError } from '../../../../relay/environment';
import { resolveLink } from '../../../../utils/Entity';
import EntitySelect, { type EntityOption } from '../form/EntitySelect';
import type { StixPathFinderQuery, StixPathFinderQuery$data } from './__generated__/StixPathFinderQuery.graphql';
import type { StixPathFinderNeighborhoodQuery, StixPathFinderNeighborhoodQuery$data } from './__generated__/StixPathFinderNeighborhoodQuery.graphql';

export const stixPathFinderQuery = graphql`
  query StixPathFinderQuery(
    $fromId: String!
    $toId: String!
    $maxDepth: Int
    $maxPaths: Int
    $relationshipTypes: [String!]
    $entityTypes: [String!]
    $includeInferred: Boolean
    $includeContainers: Boolean
  ) {
    stixPaths(
      fromId: $fromId
      toId: $toId
      maxDepth: $maxDepth
      maxPaths: $maxPaths
      relationshipTypes: $relationshipTypes
      entityTypes: $entityTypes
      includeInferred: $includeInferred
      includeContainers: $includeContainers
    ) {
      max_depth
      depth_reached
      explored_nodes
      explored_relationships
      truncated
      timed_out
      duration_ms
      paths {
        length
        node_ids
        relationship_ids
        relationship_types
        nodes {
          id
          entity_type
          representative {
            main
          }
        }
        relationships {
          ... on StixCoreRelationship {
            id
            fromId
          }
          ... on StixSightingRelationship {
            id
            fromId
          }
          ... on StixRefRelationship {
            id
            from {
              ... on StixCoreObject {
                id
              }
            }
          }
        }
      }
    }
  }
`;

const neighborhoodQuery = graphql`
  query StixPathFinderNeighborhoodQuery($id: String!) {
    stixNeighborhoodSummary(id: $id) {
      total
      truncated
      by_relationship_type {
        label
        value
      }
      by_entity_type {
        label
        value
      }
    }
  }
`;

type NeighborhoodSummary = NonNullable<StixPathFinderNeighborhoodQuery$data['stixNeighborhoodSummary']>;

export type StixPathsResult = NonNullable<StixPathFinderQuery$data['stixPaths']>;
export type StixPathResult = StixPathsResult['paths'][number];

const DEPTHS = ['1', '2', '3', '4', '5', '6'];
const PATH_COUNTS = ['1', '3', '5', '10', '20'];
const PATH_FINDER_DOCUMENTATION = 'https://docs.opencti.io/latest/usage/graph-analytics/#find-paths-between-two-entities';

interface TypeOption {
  label: string;
  value: string;
}

interface TypesComboboxProps {
  label: string;
  helperText: string;
  options: TypeOption[];
  value: TypeOption[];
  onChange: (value: TypeOption[]) => void;
}

const TypesCombobox = ({ label, helperText, options, value, onChange }: TypesComboboxProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Combobox<TypeOption>
      value={value}
      options={options}
      multiple
      isOptionEqualToValue={(option, val) => option.value === val.value}
      getOptionLabel={(option) => option?.label ?? ''}
      onValueChange={(next) => onChange((next as TypeOption[] | null) ?? [])}
    >
      <ComboboxLabel>{label}</ComboboxLabel>
      <ComboboxField>
        <ComboboxChips aria-label={label} />
        <ComboboxInput />
        <ComboboxControls>
          <ComboboxTrigger />
        </ComboboxControls>
      </ComboboxField>
      <ComboboxContent emptyMessage={t_i18n('No available options')} listAriaLabel={label} />
      <ComboboxHelperText>{helperText}</ComboboxHelperText>
    </Combobox>
  );
};

interface PathFinderSwitchProps {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  label: string;
  helperText: string;
}

const PathFinderSwitch = ({ checked, onCheckedChange, label, helperText }: PathFinderSwitchProps) => {
  const helperId = useId();
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5, flex: '1 1 240px' }}>
      <Switch checked={checked} onCheckedChange={onCheckedChange} label={label} aria-describedby={helperId} />
      <Text variant="content-caption" id={helperId}>{helperText}</Text>
    </Box>
  );
};

interface StixPathChainProps {
  path: StixPathResult;
}

/**
 * One path as a chain of entities linked by the relationship types they go through. Paths are searched in both
 * directions, so each arrow follows its relationship: "uses" from the left entity, or from the right one.
 */
export const StixPathChain = ({ path }: StixPathChainProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 0.5 }} data-testid="graph-path-chain">
      {path.nodes.map((node, index) => {
        const relationshipType = path.relationship_types[index];
        const relationship = path.relationships[index];
        let sourceId: string | undefined;
        if (relationship && 'fromId' in relationship) sourceId = relationship.fromId;
        else if (relationship && 'from' in relationship && relationship.from && 'id' in relationship.from) sourceId = relationship.from.id;
        const fromLeft = sourceId !== path.nodes[index + 1]?.id;
        return (
          <React.Fragment key={`${node.id}-${index}`}>
            <Link to={`${resolveLink(node.entity_type)}/${node.id}`} target="_blank" rel="noopener noreferrer">
              <Chip label={node.representative.main} startIcon={<ItemIcon type={node.entity_type} size="small" />} />
            </Link>
            {index < path.relationship_types.length && (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.25 }} data-testid={fromLeft ? 'graph-path-link-forward' : 'graph-path-link-backward'}>
                {!fromLeft && <WestOutlined fontSize="small" aria-hidden />}
                <Text variant="content-caption">{t_i18n(`relationship_${relationshipType}`)}</Text>
                {fromLeft && <EastOutlined fontSize="small" aria-hidden />}
              </Box>
            )}
          </React.Fragment>
        );
      })}
    </Box>
  );
};

interface StixPathFinderProps {
  fromId: string;
  fromLabel: string;
  // fixed target (investigation canvas), otherwise the user picks it
  toId?: string;
  toLabel?: string;
  renderActions: (result: StixPathsResult, selectedPaths: StixPathResult[]) => ReactNode;
}

/**
 * Paths between two entities, computed by the platform as the current user: only the entities and relationships
 * the user can access are traversed. Bounded in depth, number of paths, explored nodes and time.
 */
const StixPathFinder = ({ fromId, fromLabel, toId, toLabel, renderActions }: StixPathFinderProps) => {
  const { t_i18n, n } = useFormatter();
  const { schema } = useAuth();
  const [target, setTarget] = useState<EntityOption | null>(null);
  const [maxDepth, setMaxDepth] = useState('4');
  const [maxPaths, setMaxPaths] = useState('5');
  const [relationshipTypes, setRelationshipTypes] = useState<TypeOption[]>([]);
  const [entityTypes, setEntityTypes] = useState<TypeOption[]>([]);
  const [includeInferred, setIncludeInferred] = useState(false);
  const [includeContainers, setIncludeContainers] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<StixPathsResult | null>(null);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [neighborhood, setNeighborhood] = useState<NeighborhoodSummary | null>(null);
  const relationshipFieldRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetchQuery<StixPathFinderNeighborhoodQuery>(neighborhoodQuery, { id: fromId }).toPromise()
      .then((data) => setNeighborhood(data?.stixNeighborhoodSummary ?? null))
      .catch((err) => handleError(err));
  }, [fromId]);

  const relationshipOptions = useMemo(() => schema.scrs
    .map(({ label }) => ({ label: t_i18n(`relationship_${label}`), value: label }))
    .sort((a, b) => a.label.localeCompare(b.label)), [schema]);
  const entityTypeOptions = useMemo(() => [...schema.sdos, ...schema.scos]
    .map(({ id }) => ({ label: t_i18n(`entity_${id}`), value: id }))
    .sort((a, b) => a.label.localeCompare(b.label)), [schema]);

  // a path needs two different entities: the source itself is never a valid target
  const targetId = (toId ?? target?.value) === fromId ? undefined : (toId ?? target?.value);
  // A result is shown, and its paths acted on, only while the parameters it was searched with are the current ones
  const searchKey = (depth: string, relationships: TypeOption[], entities: TypeOption[]) => JSON.stringify([
    targetId, depth, maxPaths, relationships.map((r) => r.value), entities.map((e) => e.value), includeInferred, includeContainers,
  ]);
  const currentKey = searchKey(maxDepth, relationshipTypes, entityTypes);
  const [resultKey, setResultKey] = useState<string | null>(null);
  const latestKey = useRef(currentKey);
  const latestRequest = useRef(0);
  useEffect(() => {
    latestKey.current = currentKey;
  }, [currentKey]);
  // The next actions of an empty or limited result change a parameter and search again at once
  const findPaths = (overrides: { depth?: string; relationships?: TypeOption[]; entities?: TypeOption[] } = {}) => {
    if (!targetId) return;
    const depth = overrides.depth ?? maxDepth;
    const relationships = overrides.relationships ?? relationshipTypes;
    const entities = overrides.entities ?? entityTypes;
    const key = searchKey(depth, relationships, entities);
    latestKey.current = key;
    latestRequest.current += 1;
    const request = latestRequest.current;
    // An answer is dropped once a newer search started or the parameters changed
    const isCurrent = () => request === latestRequest.current && key === latestKey.current;
    setLoading(true);
    setResult(null);
    fetchQuery<StixPathFinderQuery>(stixPathFinderQuery, {
      fromId,
      toId: targetId,
      maxDepth: Number(depth),
      maxPaths: Number(maxPaths),
      relationshipTypes: relationships.length > 0 ? relationships.map((r) => r.value) : null,
      entityTypes: entities.length > 0 ? entities.map((e) => e.value) : null,
      includeInferred,
      includeContainers,
    }).toPromise()
      .then((data) => {
        if (!isCurrent()) return;
        const paths = data?.stixPaths ?? null;
        setResult(paths);
        setResultKey(key);
        setSelected(new Set((paths?.paths ?? []).map((_, index) => index)));
      })
      .catch((err) => {
        if (isCurrent()) handleError(err);
      })
      .finally(() => {
        if (request === latestRequest.current) setLoading(false);
      });
  };

  // Quick pivot: restrict the search to (or release) a relationship type of the starting entity
  const toggleRelationshipType = (type: string) => {
    if (relationshipTypes.some((r) => r.value === type)) {
      setRelationshipTypes(relationshipTypes.filter((r) => r.value !== type));
    } else {
      setRelationshipTypes([...relationshipTypes, { label: t_i18n(`relationship_${type}`), value: type }]);
    }
  };

  const togglePath = (index: number) => {
    const next = new Set(selected);
    if (next.has(index)) next.delete(index);
    else next.add(index);
    setSelected(next);
  };

  const allowLongerPaths = () => {
    const next = DEPTHS[DEPTHS.indexOf(maxDepth) + 1];
    if (!next) return;
    setMaxDepth(next);
    findPaths({ depth: next });
  };
  const removeTypeFilters = () => {
    setRelationshipTypes([]);
    setEntityTypes([]);
    findPaths({ relationships: [], entities: [] });
  };
  const narrowByRelationshipType = () => {
    const field = relationshipFieldRef.current;
    field?.scrollIntoView({ block: 'center', behavior: 'smooth' });
    field?.querySelector('input')?.focus();
  };
  const canAllowLongerPaths = DEPTHS.indexOf(maxDepth) < DEPTHS.length - 1;
  const hasTypeFilters = relationshipTypes.length > 0 || entityTypes.length > 0;

  const shownResult = result && resultKey === currentKey ? result : null;
  const selectedPaths = (shownResult?.paths ?? []).filter((_, index) => selected.has(index));
  const resultActions = shownResult && shownResult.paths.length > 0 ? renderActions(shownResult, selectedPaths) : null;
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }} data-testid="graph-path-finder">
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 1 }}>
        <Text variant="content-compact">
          {toId
            ? t_i18n('Paths between {from} and {to}', { values: { from: fromLabel, to: toLabel ?? '' } })
            : t_i18n('Paths from {name}', { values: { name: fromLabel } })}
        </Text>
        <Button
          variant="tertiary"
          size="small"
          href={PATH_FINDER_DOCUMENTATION}
          target="_blank"
          rel="noopener noreferrer"
          data-testid="graph-path-learn-more"
        >
          {t_i18n('Learn more')}
        </Button>
      </Box>
      {neighborhood && neighborhood.total > 0 && (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }} data-testid="graph-neighborhood-summary">
          <Text variant="content-caption">
            {neighborhood.truncated
              ? t_i18n('Neighborhood: more than {count, plural, one {# relationship} other {# relationships}}', { values: { count: neighborhood.total } })
              : t_i18n('Neighborhood: {count, plural, one {# relationship} other {# relationships}}', { values: { count: neighborhood.total } })}
          </Text>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
            {neighborhood.by_relationship_type.map(({ label, value }) => (
              <Chip
                key={label}
                label={`${t_i18n(`relationship_${label}`)} (${n(value)})`}
                severity={relationshipTypes.some((r) => r.value === label) ? 'info' : 'neutral'}
                onClick={() => toggleRelationshipType(label)}
              />
            ))}
          </Box>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
            {neighborhood.by_entity_type.slice(0, 12).map(({ label, value }) => (
              <Chip key={label} label={`${t_i18n(`entity_${label}`)} (${n(value)})`} startIcon={<ItemIcon type={label} size="small" />} />
            ))}
          </Box>
        </Box>
      )}
      {!toId && (
        <EntitySelect
          label={t_i18n('Target entity')}
          helperText={neighborhood && neighborhood.total > 0
            ? t_i18n('The entity to connect {name} to. Until you pick one, the chips above summarize the neighborhood of {name}: click a relationship type to search through it only.', { values: { name: fromLabel } })
            : t_i18n('The entity to connect {name} to, searched by name among the entities you can access.', { values: { name: fromLabel } })}
          types={['Stix-Core-Object']}
          multiple={false}
          value={target}
          onChange={(value) => setTarget(value as EntityOption | null)}
          excludedIds={[fromId]}
        />
      )}
      <Box sx={{ display: 'flex', gap: 2 }}>
        <Box sx={{ flex: 1 }}>
          <Select value={maxDepth} onValueChange={setMaxDepth}>
            <SelectLabel>{t_i18n('Maximum path length')}</SelectLabel>
            <SelectTrigger aria-label={t_i18n('Maximum path length')}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Maximum path length')}>
              {DEPTHS.map((depth) => <SelectItem key={depth} value={depth}>{depth}</SelectItem>)}
            </SelectContent>
            <SelectHelperText>
              {t_i18n('One hop is one relationship: an intrusion set that uses a malware communicating with an IP address is a path of length 2. Longer paths reach more distant entities and take longer to search.')}
            </SelectHelperText>
          </Select>
        </Box>
        <Box sx={{ flex: 1 }}>
          <Select value={maxPaths} onValueChange={setMaxPaths}>
            <SelectLabel>{t_i18n('Number of paths')}</SelectLabel>
            <SelectTrigger aria-label={t_i18n('Number of paths')}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Number of paths')}>
              {PATH_COUNTS.map((count) => <SelectItem key={count} value={count}>{count}</SelectItem>)}
            </SelectContent>
            <SelectHelperText>
              {t_i18n('How many paths to list, the shortest first. A higher number shows more alternative routes between the two entities.')}
            </SelectHelperText>
          </Select>
        </Box>
      </Box>
      <Box ref={relationshipFieldRef}>
        <TypesCombobox
          label={t_i18n('Relationship types (all by default)')}
          helperText={t_i18n('Only follow these relationships, for example "{first}" and "{second}" to trace the tools used and their network activity.', {
            values: { first: t_i18n('relationship_uses'), second: t_i18n('relationship_communicates-with') },
          })}
          options={relationshipOptions}
          value={relationshipTypes}
          onChange={setRelationshipTypes}
        />
      </Box>
      <TypesCombobox
        label={t_i18n('Intermediate entity types (all by default)')}
        helperText={t_i18n('Only go through these entity types between the two entities, for example {first} and {second}. The two entities you connect are always kept.', {
          values: { first: t_i18n('entity_Malware'), second: t_i18n('entity_Infrastructure') },
        })}
        options={entityTypeOptions}
        value={entityTypes}
        onChange={setEntityTypes}
      />
      <Box sx={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
        <PathFinderSwitch
          checked={includeInferred}
          onCheckedChange={setIncludeInferred}
          label={t_i18n('Include inferred relationships')}
          helperText={t_i18n('Also follow the relationships created by the inference rules of the platform. Off: only the relationships stored in the knowledge are followed.')}
        />
        <PathFinderSwitch
          checked={includeContainers}
          onCheckedChange={setIncludeContainers}
          label={t_i18n('Go through containers')}
          helperText={t_i18n('Also link two entities through a report, a grouping or a case that contains them both, for example two indicators listed in the same report.')}
        />
      </Box>
      {loading && <Loader variant={LoaderVariant.inElement} />}
      {shownResult && (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }} data-testid="graph-path-results">
          <Text variant="content-caption">
            {t_i18n('{entities, plural, one {# entity} other {# entities}} and {relationships, plural, one {# relationship} other {# relationships}} explored in {duration} ms', {
              values: { entities: shownResult.explored_nodes, relationships: shownResult.explored_relationships, duration: n(shownResult.duration_ms) },
            })}
          </Text>
          {(shownResult.truncated || shownResult.timed_out) && (
            <Alert
              severity="warning"
              elevation={1}
              data-testid="graph-path-limit"
              title={shownResult.timed_out
                ? t_i18n('The search reached its time limit, longer paths may exist.')
                : t_i18n('The search reached its exploration limit, narrow it with relationship or entity types.')}
              action={(
                <Button variant="secondary" size="small" onClick={narrowByRelationshipType}>
                  {t_i18n('Narrow by relationship type')}
                </Button>
              )}
            />
          )}
          {shownResult.paths.length === 0 ? (
            <Alert
              severity="info"
              elevation={1}
              data-testid="graph-path-empty"
              title={t_i18n('No path found within these limits between entities you can access.')}
              action={(canAllowLongerPaths || hasTypeFilters) && (
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  {canAllowLongerPaths && (
                    <Button variant="secondary" size="small" onClick={allowLongerPaths} disabled={loading}>
                      {t_i18n('Allow longer paths')}
                    </Button>
                  )}
                  {hasTypeFilters && (
                    <Button variant="secondary" size="small" onClick={removeTypeFilters} disabled={loading}>
                      {t_i18n('Remove the type filters')}
                    </Button>
                  )}
                </Box>
              )}
            />
          ) : shownResult.paths.map((path, index) => (
            <Box key={path.relationship_ids.join('|')} sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Checkbox
                checked={selected.has(index)}
                onCheckedChange={() => togglePath(index)}
                aria-label={t_i18n('Select path {number}', { values: { number: index + 1 } })}
              />
              <StixPathChain path={path} />
            </Box>
          ))}
        </Box>
      )}
      <Box
        sx={{
          position: 'sticky',
          bottom: 0,
          zIndex: 1,
          backgroundColor: 'var(--bg-elevation-default)',
          py: 1.5,
          display: 'flex',
          justifyContent: 'flex-end',
          flexWrap: 'wrap',
          gap: 1,
        }}
        data-testid="graph-path-footer"
      >
        <Button
          variant={resultActions ? 'secondary' : 'primary'}
          onClick={() => findPaths()}
          disabled={!targetId || loading}
          data-testid="graph-path-find"
        >
          {t_i18n('Find paths')}
        </Button>
        {resultActions}
      </Box>
    </Box>
  );
};

export default StixPathFinder;
