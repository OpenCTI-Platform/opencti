import React, { ReactNode, useMemo, useState } from 'react';
import { graphql } from 'react-relay';
import { Link } from 'react-router';
import {
  Checkbox,
  Chip,
  Combobox,
  ComboboxChips,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
  Select,
  SelectContent,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
  Switch,
  Text,
} from '@filigran/design-system';
import { Alert, Box } from '@mui/material';
import { ArrowRightAltOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import ItemIcon from '../../../../components/ItemIcon';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';
import { fetchQuery } from '../../../../relay/environment';
import { resolveLink } from '../../../../utils/Entity';
import EntitySelect, { type EntityOption } from '../form/EntitySelect';
import type { StixPathFinderQuery, StixPathFinderQuery$data } from './__generated__/StixPathFinderQuery.graphql';

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
      }
    }
  }
`;

export type StixPathsResult = NonNullable<StixPathFinderQuery$data['stixPaths']>;
export type StixPathResult = StixPathsResult['paths'][number];

const DEPTHS = ['1', '2', '3', '4', '5', '6'];
const PATH_COUNTS = ['1', '3', '5', '10', '20'];

interface TypeOption {
  label: string;
  value: string;
}

interface TypesComboboxProps {
  label: string;
  options: TypeOption[];
  value: TypeOption[];
  onChange: (value: TypeOption[]) => void;
}

const TypesCombobox = ({ label, options, value, onChange }: TypesComboboxProps) => {
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
    </Combobox>
  );
};

interface StixPathChainProps {
  path: StixPathResult;
}

/** One path as a chain of entities linked by the relationship types they go through. */
export const StixPathChain = ({ path }: StixPathChainProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 0.5 }} data-testid="graph-path-chain">
      {path.nodes.map((node, index) => (
        <React.Fragment key={`${node.id}-${index}`}>
          <Link to={`${resolveLink(node.entity_type)}/${node.id}`} target="_blank" rel="noopener noreferrer">
            <Chip label={node.representative.main} startIcon={<ItemIcon type={node.entity_type} size="small" />} />
          </Link>
          {index < path.relationship_types.length && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.25 }}>
              <Text variant="content-caption">{t_i18n(`relationship_${path.relationship_types[index]}`)}</Text>
              <ArrowRightAltOutlined fontSize="small" />
            </Box>
          )}
        </React.Fragment>
      ))}
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

  const relationshipOptions = useMemo(() => schema.scrs
    .map(({ label }) => ({ label: t_i18n(`relationship_${label}`), value: label }))
    .sort((a, b) => a.label.localeCompare(b.label)), [schema]);
  const entityTypeOptions = useMemo(() => [...schema.sdos, ...schema.scos]
    .map(({ id }) => ({ label: t_i18n(`entity_${id}`), value: id }))
    .sort((a, b) => a.label.localeCompare(b.label)), [schema]);

  const targetId = toId ?? target?.value;
  const findPaths = () => {
    if (!targetId) return;
    setLoading(true);
    setResult(null);
    fetchQuery<StixPathFinderQuery>(stixPathFinderQuery, {
      fromId,
      toId: targetId,
      maxDepth: Number(maxDepth),
      maxPaths: Number(maxPaths),
      relationshipTypes: relationshipTypes.length > 0 ? relationshipTypes.map((r) => r.value) : null,
      entityTypes: entityTypes.length > 0 ? entityTypes.map((e) => e.value) : null,
      includeInferred,
      includeContainers,
    }).toPromise()
      .then((data) => {
        const paths = data?.stixPaths ?? null;
        setResult(paths);
        setSelected(new Set((paths?.paths ?? []).map((_, index) => index)));
      })
      .finally(() => setLoading(false));
  };

  const togglePath = (index: number) => {
    const next = new Set(selected);
    if (next.has(index)) next.delete(index);
    else next.add(index);
    setSelected(next);
  };

  const selectedPaths = (result?.paths ?? []).filter((_, index) => selected.has(index));
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }} data-testid="graph-path-finder">
      <Text variant="content-compact">
        {toId
          ? `${t_i18n('Paths between')} ${fromLabel} ${t_i18n('and')} ${toLabel ?? ''}`
          : `${t_i18n('Paths from')} ${fromLabel}`}
      </Text>
      {!toId && (
        <EntitySelect
          label={t_i18n('Target entity')}
          types={['Stix-Core-Object']}
          multiple={false}
          value={target}
          onChange={(value) => setTarget(value as EntityOption | null)}
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
          </Select>
        </Box>
      </Box>
      <TypesCombobox
        label={t_i18n('Relationship types (all by default)')}
        options={relationshipOptions}
        value={relationshipTypes}
        onChange={setRelationshipTypes}
      />
      <TypesCombobox
        label={t_i18n('Intermediate entity types (all by default)')}
        options={entityTypeOptions}
        value={entityTypes}
        onChange={setEntityTypes}
      />
      <Box sx={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
        <Switch checked={includeInferred} onCheckedChange={setIncludeInferred} label={t_i18n('Include inferred relationships')} />
        <Switch checked={includeContainers} onCheckedChange={setIncludeContainers} label={t_i18n('Go through containers')} />
      </Box>
      <Box>
        <Button onClick={findPaths} disabled={!targetId || loading} data-testid="graph-path-find">
          {t_i18n('Find paths')}
        </Button>
      </Box>
      {loading && <Loader variant={LoaderVariant.inElement} />}
      {result && (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }} data-testid="graph-path-results">
          <Text variant="content-caption">
            {`${n(result.explored_nodes)} ${t_i18n('entities explored')} - ${n(result.explored_relationships)} ${t_i18n('relationships explored')} - ${result.duration_ms} ms`}
          </Text>
          {(result.truncated || result.timed_out) && (
            <Alert severity="warning" variant="outlined">
              {result.timed_out
                ? t_i18n('The search reached its time limit, longer paths may exist.')
                : t_i18n('The search reached its exploration limit, narrow it with relationship or entity types.')}
            </Alert>
          )}
          {result.paths.length === 0 ? (
            <Alert severity="info" variant="outlined">
              {t_i18n('No path found within these limits between entities you can access.')}
            </Alert>
          ) : result.paths.map((path, index) => (
            <Box key={path.relationship_ids.join('|')} sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Checkbox
                checked={selected.has(index)}
                onCheckedChange={() => togglePath(index)}
                aria-label={`${t_i18n('Select path')} ${index + 1}`}
              />
              <StixPathChain path={path} />
            </Box>
          ))}
          {result.paths.length > 0 && renderActions(result, selectedPaths)}
        </Box>
      )}
    </Box>
  );
};

export default StixPathFinder;
