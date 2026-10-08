import React, { Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePaginationFragment, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { Link } from 'react-router';
import { Box, DialogActions, List, ListItem, ListItemIcon, ListItemText, Stack, Typography } from '@mui/material';
import { DeleteOutlined } from '@mui/icons-material';
import { IconButton, Input } from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import StixCoreRelationshipCreationFromEntity from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import Card from '../../../../components/common/card/Card';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { notifyPayloadErrors } from './defenseMutation-utils';
import { MAX_DECLARED_LOGSOURCES, MAX_LOGSOURCE_VALUE_LENGTH } from './defenseMatrix-utils';
import DefenseDisabledReason from './DefenseDisabledReason';
import { DefenseProvidedDataComponentsQuery } from './__generated__/DefenseProvidedDataComponentsQuery.graphql';
import { DefenseProvidedDataComponentsRefetchQuery } from './__generated__/DefenseProvidedDataComponentsRefetchQuery.graphql';
import { DefenseProvidedDataComponents_data$key } from './__generated__/DefenseProvidedDataComponents_data.graphql';
import { DefenseProvidedDataComponentsDeleteMutation } from './__generated__/DefenseProvidedDataComponentsDeleteMutation.graphql';
import { DefenseProvidedDataComponentsLogsourcesMutation } from './__generated__/DefenseProvidedDataComponentsLogsourcesMutation.graphql';

const PROVIDES = 'provides';
const PROVIDED_PAGE_SIZE = 100;

// A revoked declaration, or one of a revoked data component, provides no telemetry to the levels: the list shows the
// declarations they count. The revoked data components are left out once loaded, the relationships cannot filter on them.
const ACTIVE_PROVIDES_FILTERS = { mode: 'and' as const, filters: [{ key: ['revoked'], values: ['false'] }], filterGroups: [] };

const defenseProvidedDataComponentsQuery = graphql`
  query DefenseProvidedDataComponentsQuery($fromId: [String], $filters: FilterGroup, $count: Int!, $cursor: ID) {
    ...DefenseProvidedDataComponents_data @arguments(fromId: $fromId, filters: $filters, count: $count, cursor: $cursor)
  }
`;

const defenseProvidedDataComponentsFragment = graphql`
  fragment DefenseProvidedDataComponents_data on Query
  @argumentDefinitions(
    fromId: { type: "[String]" }
    filters: { type: "FilterGroup" }
    count: { type: "Int", defaultValue: 100 }
    cursor: { type: "ID" }
  ) @refetchable(queryName: "DefenseProvidedDataComponentsRefetchQuery") {
    stixCoreRelationships(
      fromId: $fromId
      relationship_type: ["provides"]
      filters: $filters
      first: $count
      after: $cursor
      orderBy: created_at
      orderMode: desc
    )
    @connection(key: "Pagination_defenseProvidedDataComponents_stixCoreRelationships") {
      edges {
        node {
          id
          description
          to {
            ... on DataComponent {
              id
              name
              entity_type
              revoked
            }
          }
        }
      }
      pageInfo {
        endCursor
        hasNextPage
      }
    }
  }
`;

const defenseProvidedDataComponentsDeleteMutation = graphql`
  mutation DefenseProvidedDataComponentsDeleteMutation($id: ID!) {
    stixCoreRelationshipEdit(id: $id) {
      delete
    }
  }
`;

const defenseProvidedDataComponentsLogsourcesMutation = graphql`
  mutation DefenseProvidedDataComponentsLogsourcesMutation($id: ID!, $logsources: [DefenseLogsourceInput!]!) {
    defensePlatformProvidesFromLogsources(id: $id, logsources: $logsources) {
      created_count
      existing_count
      unmatched_data_components
      dataComponents {
        id
        name
      }
    }
  }
`;

interface Logsource {
  category: string;
  product: string;
  service: string;
}

const logsourceLabel = (logsource: Logsource) => ['category', 'product', 'service']
  .map((key) => (logsource[key as keyof Logsource] ? `${key}:${logsource[key as keyof Logsource]}` : null))
  .filter(Boolean)
  .join(' ');

export const LogsourcesDialog = ({ entityId, open, onClose, onDone }: { entityId: string; open: boolean; onClose: () => void; onDone: () => void }) => {
  const { t_i18n } = useFormatter();
  const [current, setCurrent] = useState<Logsource>({ category: '', product: '', service: '' });
  const [logsources, setLogsources] = useState<Logsource[]>([]);
  const [result, setResult] = useState<{ created: number; existing: number; unmatched: readonly string[] } | null>(null);
  const [commit, inFlight] = useApiMutation<DefenseProvidedDataComponentsLogsourcesMutation>(defenseProvidedDataComponentsLogsourcesMutation);
  const hasField = current.category.trim() || current.product.trim() || current.service.trim();
  const full = logsources.length >= MAX_DECLARED_LOGSOURCES;
  const canAdd = hasField && !full;
  let addReason: string | undefined;
  if (full) {
    addReason = t_i18n('A declaration holds at most {max} log sources: declare them, then add the others.', { values: { max: MAX_DECLARED_LOGSOURCES } });
  } else if (!hasField) {
    addReason = t_i18n('Enter a category, a product or a service');
  }

  const addCurrent = () => {
    if (!canAdd) return;
    setLogsources([...logsources, { category: current.category.trim(), product: current.product.trim(), service: current.service.trim() }]);
    setCurrent({ category: '', product: '', service: '' });
  };
  const close = () => {
    setLogsources([]);
    setResult(null);
    onClose();
  };
  const submit = () => {
    commit({
      variables: {
        id: entityId,
        logsources: logsources.map((l) => ({ category: l.category || null, product: l.product || null, service: l.service || null })),
      },
      onCompleted: (response, errors) => {
        const payload = response.defensePlatformProvidesFromLogsources;
        if (notifyPayloadErrors(errors) || !payload) return;
        setResult({ created: payload.created_count, existing: payload.existing_count, unmatched: payload.unmatched_data_components });
        setLogsources([]);
        onDone();
      },
    });
  };

  return (
    <Dialog
      open={open}
      onClose={close}
      title={t_i18n('Declare telemetry from log sources')}
      size="medium"
      contentProps={{ style: { display: 'flex', flexDirection: 'column', overflowY: 'hidden' } }}
    >
      {/* The body scrolls on its own so the footer stays in view with a long list; the 4px padding given back and
          taken out again keeps the focus ring the library paints outside the fields. */}
      <Box
        data-testid="defense-logsource-body"
        style={{ flex: '1 1 auto', minHeight: 0, overflowY: 'auto', position: 'relative', padding: 4, margin: -4 }}
      >
        <Typography variant="body2">
          {t_i18n('Describe the log sources collected by this platform with the Sigma taxonomy. The telemetry mappings turn them into the data components the platform provides.')}
        </Typography>
        <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: 1, alignItems: 'end', marginTop: 2 }}>
          <Input label={t_i18n('Category')} value={current.category} maxLength={MAX_LOGSOURCE_VALUE_LENGTH} onChange={(e) => setCurrent({ ...current, category: e.target.value })} placeholder="process_creation" />
          <Input label={t_i18n('Product')} value={current.product} maxLength={MAX_LOGSOURCE_VALUE_LENGTH} onChange={(e) => setCurrent({ ...current, product: e.target.value })} placeholder="windows" />
          <Input label={t_i18n('Service')} value={current.service} maxLength={MAX_LOGSOURCE_VALUE_LENGTH} onChange={(e) => setCurrent({ ...current, service: e.target.value })} placeholder="sysmon" />
          <DefenseDisabledReason label={t_i18n('Add')} reason={addReason}>
            <Button variant="secondary" onClick={addCurrent} disabled={!canAdd} data-testid="defense-logsource-add">{t_i18n('Add')}</Button>
          </DefenseDisabledReason>
        </Box>
        <Typography variant="caption" color="text.secondary" component="p" sx={{ marginTop: 0.5 }} data-testid="defense-logsource-help">
          {t_i18n('A log source names the data a rule reads, with the Sigma fields category, product and service. One of the three is enough.')}
        </Typography>
        {logsources.length > 0 && (
          <Typography variant="body2" color="text.secondary" sx={{ marginTop: 2 }} data-testid="defense-logsource-count">
            {t_i18n('{count, plural, one {# log source} other {# log sources}}', { values: { count: logsources.length } })}
          </Typography>
        )}
        {logsources.length > 0 && (
          <List dense aria-label={t_i18n('Log sources')}>
            {logsources.map((logsource, index) => (
              <ListItem
                key={`${logsourceLabel(logsource)}-${index}`}
                disableGutters
                secondaryAction={(
                  <IconButton
                    size="sm"
                    priority="tertiary"
                    aria-label={t_i18n('Remove {name}', { values: { name: logsourceLabel(logsource) } })}
                    icon={<DeleteOutlined fontSize="small" />}
                    onClick={() => setLogsources(logsources.filter((_, i) => i !== index))}
                  />
                )}
              >
                <ListItemText primary={logsourceLabel(logsource)} />
              </ListItem>
            ))}
          </List>
        )}
        {result && (
          <Box sx={{ marginTop: 2 }} data-testid="defense-logsource-result">
            <Typography variant="body2">
              {t_i18n('{count, plural, =0 {No new data component declared} one {# data component declared} other {# data components declared}}', { values: { count: result.created } })}
            </Typography>
            {result.existing > 0 && (
              <Typography variant="body2" color="text.secondary">
                {t_i18n('{count, plural, one {# data component was already declared} other {# data components were already declared}}', { values: { count: result.existing } })}
              </Typography>
            )}
            {result.unmatched.length > 0 && (
              <Typography variant="body2" color="warning.main">
                {`${t_i18n('Data components not found in the platform')}: ${result.unmatched.join(', ')}`}
              </Typography>
            )}
          </Box>
        )}
      </Box>
      <DialogActions sx={{ paddingX: 0, marginTop: 2, flexShrink: 0 }}>
        <Button variant="secondary" onClick={close}>{t_i18n('Close')}</Button>
        <DefenseDisabledReason label={t_i18n('Declare')} reason={!inFlight && logsources.length === 0 ? t_i18n('Add at least one log source') : undefined}>
          <Button onClick={submit} disabled={inFlight || logsources.length === 0} data-testid="defense-logsource-submit">
            {t_i18n('Declare')}
          </Button>
        </DefenseDisabledReason>
      </DialogActions>
    </Dialog>
  );
};

const ProvidedList = ({ queryRef, onDeleted }: { queryRef: PreloadedQuery<DefenseProvidedDataComponentsQuery>; onDeleted: () => void }) => {
  const { t_i18n } = useFormatter();
  const queryData = usePreloadedQuery(defenseProvidedDataComponentsQuery, queryRef);
  const { data, hasNext, loadNext, isLoadingNext } = usePaginationFragment<DefenseProvidedDataComponentsRefetchQuery, DefenseProvidedDataComponents_data$key>(
    defenseProvidedDataComponentsFragment,
    queryData,
  );
  const [commitDelete, deleting] = useApiMutation<DefenseProvidedDataComponentsDeleteMutation>(defenseProvidedDataComponentsDeleteMutation);
  const [toRemove, setToRemove] = useState<{ id: string; name: string } | null>(null);
  const relations = (data.stixCoreRelationships?.edges ?? []).map(({ node }) => node).filter((node) => !!node.to?.id && !node.to.revoked);
  if (relations.length === 0 && !hasNext) {
    return <WidgetNoData message={t_i18n('No data component is declared as provided.')} />;
  }
  const remove = () => toRemove && commitDelete({
    variables: { id: toRemove.id },
    onCompleted: (_, errors) => {
      if (notifyPayloadErrors(errors)) return;
      setToRemove(null);
      onDeleted();
    },
  });
  return (
    <>
      <Dialog open={!!toRemove} onClose={() => setToRemove(null)} title={t_i18n('Remove provided telemetry')} size="small">
        <Typography>
          {t_i18n('The platform will no longer provide {name}. Techniques detected only through this data component lose their telemetry level at the next computation.', { values: { name: toRemove?.name ?? '' } })}
        </Typography>
        <DialogActions sx={{ paddingX: 0, marginTop: 2 }}>
          <Button variant="secondary" onClick={() => setToRemove(null)} disabled={deleting}>{t_i18n('Cancel')}</Button>
          <Button intent="destructive" onClick={remove} disabled={deleting} data-testid="defense-provided-remove-confirm">{t_i18n('Remove')}</Button>
        </DialogActions>
      </Dialog>
      <ProvidedListItems relations={relations} onRemove={setToRemove} />
      {hasNext && (
        <Box sx={{ display: 'flex', justifyContent: 'center', marginTop: 2 }}>
          <Button variant="secondary" disabled={isLoadingNext} onClick={() => loadNext(PROVIDED_PAGE_SIZE)} data-testid="defense-provided-load-more">
            {t_i18n('Load more')}
          </Button>
        </Box>
      )}
    </>
  );
};

const ProvidedListItems = ({ relations, onRemove }: {
  relations: ReadonlyArray<{ id: string; description?: string | null; to?: { id?: string; name?: string } | null }>;
  onRemove: (relation: { id: string; name: string }) => void;
}) => {
  const { t_i18n } = useFormatter();
  return (
    <List dense disablePadding data-testid="defense-provided-list">
      {relations.map((relation) => (
        <ListItem
          key={relation.id}
          divider
          disableGutters
          secondaryAction={(
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <IconButton
                size="sm"
                priority="tertiary"
                aria-label={t_i18n('Remove {name}', { values: { name: relation.to?.name ?? '' } })}
                icon={<DeleteOutlined fontSize="small" />}
                onClick={() => onRemove({ id: relation.id, name: relation.to?.name ?? '' })}
              />
            </Security>
          )}
        >
          <ListItemIcon><ItemIcon type="Data-Component" /></ListItemIcon>
          <ListItemText
            primary={<Link to={`/dashboard/techniques/data_components/${relation.to?.id}`}>{relation.to?.name}</Link>}
            secondary={relation.description}
          />
        </ListItem>
      ))}
    </List>
  );
};

interface DefenseProvidedDataComponentsProps {
  entityId: string;
}

/**
 * Telemetry declared for a security platform: the data components it provides, added through the
 * standard relationship creation or from log sources through the telemetry mappings.
 */
const DefenseProvidedDataComponents = ({ entityId }: DefenseProvidedDataComponentsProps) => {
  const { t_i18n } = useFormatter();
  const [queryRef, loadQuery] = useQueryLoader<DefenseProvidedDataComponentsQuery>(defenseProvidedDataComponentsQuery);
  const [logsourcesOpen, setLogsourcesOpen] = useState(false);

  const reload = () => loadQuery({ fromId: [entityId], filters: ACTIVE_PROVIDES_FILTERS, count: PROVIDED_PAGE_SIZE }, { fetchPolicy: 'network-only' });
  React.useEffect(() => {
    reload();
  }, [entityId]);

  return (
    <Card
      title={t_i18n('Provided telemetry')}
      action={(
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <Stack direction="row" spacing={1} alignItems="center">
            <Button variant="secondary" onClick={() => setLogsourcesOpen(true)} data-testid="defense-logsources-open">
              {t_i18n('Declare from log sources')}
            </Button>
            <StixCoreRelationshipCreationFromEntity
              entityId={entityId}
              variant="inLine"
              inLineSize="default"
              allowedRelationshipTypes={[PROVIDES]}
              targetStixDomainObjectTypes={['Data-Component']}
              paginationOptions={{}}
              paddingRight={0}
              onCreate={reload}
            />
          </Stack>
        </Security>
      )}
    >
      {queryRef ? (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <ProvidedList queryRef={queryRef} onDeleted={reload} />
        </Suspense>
      ) : <Loader variant={LoaderVariant.inElement} />}
      <LogsourcesDialog entityId={entityId} open={logsourcesOpen} onClose={() => setLogsourcesOpen(false)} onDone={reload} />
    </Card>
  );
};

export default DefenseProvidedDataComponents;
