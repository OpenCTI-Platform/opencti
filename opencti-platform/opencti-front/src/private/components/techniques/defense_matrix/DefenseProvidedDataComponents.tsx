import React, { Suspense, useRef, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { Link } from 'react-router';
import { Box, DialogActions, List, ListItem, ListItemIcon, ListItemText, Stack, Typography } from '@mui/material';
import { DeleteOutlined } from '@mui/icons-material';
import {
  Combobox,
  ComboboxChips,
  ComboboxClear,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
  IconButton,
  Input,
} from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import Card from '../../../../components/common/card/Card';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import { DefenseProvidedDataComponentsQuery } from './__generated__/DefenseProvidedDataComponentsQuery.graphql';
import { DefenseProvidedDataComponentsSearchQuery$data } from './__generated__/DefenseProvidedDataComponentsSearchQuery.graphql';
import { DefenseProvidedDataComponentsAddMutation } from './__generated__/DefenseProvidedDataComponentsAddMutation.graphql';
import { DefenseProvidedDataComponentsDeleteMutation } from './__generated__/DefenseProvidedDataComponentsDeleteMutation.graphql';
import { DefenseProvidedDataComponentsLogsourcesMutation } from './__generated__/DefenseProvidedDataComponentsLogsourcesMutation.graphql';

const PROVIDES = 'provides';
const MAX_PROVIDED = 500;

const defenseProvidedDataComponentsQuery = graphql`
  query DefenseProvidedDataComponentsQuery($fromId: [String], $first: Int) {
    stixCoreRelationships(fromId: $fromId, relationship_type: ["provides"], first: $first, orderBy: created_at, orderMode: desc) {
      edges {
        node {
          id
          description
          to {
            ... on DataComponent {
              id
              name
              entity_type
            }
          }
        }
      }
    }
  }
`;

const defenseProvidedDataComponentsSearchQuery = graphql`
  query DefenseProvidedDataComponentsSearchQuery($search: String) {
    dataComponents(search: $search, first: 50, orderBy: name, orderMode: asc) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const defenseProvidedDataComponentsAddMutation = graphql`
  mutation DefenseProvidedDataComponentsAddMutation($input: StixCoreRelationshipAddInput!) {
    stixCoreRelationshipAdd(input: $input) {
      id
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
      unmatched_data_components
      dataComponents {
        id
        name
      }
    }
  }
`;

interface DataComponentOption {
  value: string;
  label: string;
}

interface Logsource {
  category: string;
  product: string;
  service: string;
}

const logsourceLabel = (logsource: Logsource) => ['category', 'product', 'service']
  .map((key) => (logsource[key as keyof Logsource] ? `${key}:${logsource[key as keyof Logsource]}` : null))
  .filter(Boolean)
  .join(' ');

const LogsourcesDialog = ({ entityId, open, onClose, onDone }: { entityId: string; open: boolean; onClose: () => void; onDone: () => void }) => {
  const { t_i18n } = useFormatter();
  const [current, setCurrent] = useState<Logsource>({ category: '', product: '', service: '' });
  const [logsources, setLogsources] = useState<Logsource[]>([]);
  const [result, setResult] = useState<{ created: number; unmatched: readonly string[] } | null>(null);
  const [commit, inFlight] = useApiMutation<DefenseProvidedDataComponentsLogsourcesMutation>(defenseProvidedDataComponentsLogsourcesMutation);
  const canAdd = current.category.trim() || current.product.trim() || current.service.trim();

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
      onCompleted: (response) => {
        const payload = response.defensePlatformProvidesFromLogsources;
        setResult({ created: payload?.created_count ?? 0, unmatched: payload?.unmatched_data_components ?? [] });
        setLogsources([]);
        onDone();
      },
    });
  };

  return (
    <Dialog open={open} onClose={close} title={t_i18n('Declare telemetry from log sources')} size="medium">
      <Typography variant="body2">
        {t_i18n('Describe the log sources collected by this platform with the Sigma taxonomy. The log source mapping turns them into the data components the platform provides.')}
      </Typography>
      <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: 1, alignItems: 'end', marginTop: 2 }}>
        <Input label={t_i18n('Category')} value={current.category} onChange={(e) => setCurrent({ ...current, category: e.target.value })} placeholder="process_creation" />
        <Input label={t_i18n('Product')} value={current.product} onChange={(e) => setCurrent({ ...current, product: e.target.value })} placeholder="windows" />
        <Input label={t_i18n('Service')} value={current.service} onChange={(e) => setCurrent({ ...current, service: e.target.value })} placeholder="sysmon" />
        <Button variant="secondary" onClick={addCurrent} disabled={!canAdd} data-testid="defense-logsource-add">{t_i18n('Add')}</Button>
      </Box>
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
                  aria-label={t_i18n('Remove')}
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
          <Typography variant="body2">{t_i18n('{count} data components declared', { values: { count: result.created } })}</Typography>
          {result.unmatched.length > 0 && (
            <Typography variant="body2" color="warning.main">
              {`${t_i18n('Data components not found in the platform')}: ${result.unmatched.join(', ')}`}
            </Typography>
          )}
        </Box>
      )}
      <DialogActions sx={{ paddingX: 0, marginTop: 2 }}>
        <Button variant="secondary" onClick={close}>{t_i18n('Close')}</Button>
        <Button onClick={submit} disabled={inFlight || logsources.length === 0} data-testid="defense-logsource-submit">
          {t_i18n('Declare')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

const ProvidedList = ({ queryRef, onDeleted }: { queryRef: PreloadedQuery<DefenseProvidedDataComponentsQuery>; onDeleted: () => void }) => {
  const { t_i18n } = useFormatter();
  const { stixCoreRelationships } = usePreloadedQuery(defenseProvidedDataComponentsQuery, queryRef);
  const [commitDelete] = useApiMutation<DefenseProvidedDataComponentsDeleteMutation>(defenseProvidedDataComponentsDeleteMutation);
  const relations = (stixCoreRelationships?.edges ?? []).map(({ node }) => node).filter((node) => !!node.to?.id);
  if (relations.length === 0) {
    return <Typography variant="body2" color="text.secondary">{t_i18n('No data component is declared as provided.')}</Typography>;
  }
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
                onClick={() => commitDelete({ variables: { id: relation.id }, onCompleted: onDeleted })}
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
 * Telemetry declared for a security platform or a system: the data components it provides,
 * added one by one or from log sources through the log source mapping.
 */
const DefenseProvidedDataComponents = ({ entityId }: DefenseProvidedDataComponentsProps) => {
  const { t_i18n } = useFormatter();
  const [queryRef, loadQuery] = useQueryLoader<DefenseProvidedDataComponentsQuery>(defenseProvidedDataComponentsQuery);
  const [options, setOptions] = useState<DataComponentOption[]>([]);
  const [selected, setSelected] = useState<DataComponentOption[]>([]);
  const [logsourcesOpen, setLogsourcesOpen] = useState(false);
  const [adding, setAdding] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [commitAdd] = useApiMutation<DefenseProvidedDataComponentsAddMutation>(defenseProvidedDataComponentsAddMutation);

  const reload = () => loadQuery({ fromId: [entityId], first: MAX_PROVIDED }, { fetchPolicy: 'network-only' });
  React.useEffect(() => {
    reload();
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, [entityId]);

  const search = (input: string) => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      fetchQuery(defenseProvidedDataComponentsSearchQuery, { search: input })
        .toPromise()
        .then((data) => {
          const edges = (data as DefenseProvidedDataComponentsSearchQuery$data | undefined)?.dataComponents?.edges ?? [];
          setOptions(edges.flatMap((edge) => (edge?.node ? [{ value: edge.node.id, label: edge.node.name }] : [])));
        });
    }, 300);
  };

  const addSelected = async () => {
    setAdding(true);
    const results = await Promise.allSettled(selected.map((option) => new Promise<void>((resolve, reject) => {
      commitAdd({
        variables: { input: { fromId: entityId, toId: option.value, relationship_type: PROVIDES } },
        onCompleted: () => resolve(),
        onError: (error) => reject(error),
      });
    })));
    setAdding(false);
    const failed = results.filter((r) => r.status === 'rejected').length;
    if (failed === 0) {
      MESSAGING$.notifySuccess(t_i18n('{count} data components declared', { values: { count: selected.length } }));
    }
    setSelected([]);
    reload();
  };

  return (
    <Card
      title={t_i18n('Provided telemetry')}
      action={(
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <Button variant="secondary" onClick={() => setLogsourcesOpen(true)} data-testid="defense-logsources-open">
            {t_i18n('Declare from log sources')}
          </Button>
        </Security>
      )}
    >
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <Stack direction="row" spacing={1} alignItems="flex-end" sx={{ marginBottom: 2 }}>
          <Box sx={{ flex: 1 }}>
            <Combobox<DataComponentOption>
              multiple
              className="w-full"
              options={options}
              value={selected}
              getOptionLabel={(o) => o.label}
              isOptionEqualToValue={(a, b) => a.value === b.value}
              filterOptions={(all) => all}
              onInputChange={(input) => search(input)}
              onOpenChange={(open) => {
                if (open && options.length === 0) search('');
              }}
              onValueChange={(next) => setSelected((next as DataComponentOption[] | null) ?? [])}
            >
              <ComboboxLabel>{t_i18n('Data components')}</ComboboxLabel>
              <ComboboxField>
                <ComboboxChips aria-label={t_i18n('Data components')} />
                <ComboboxInput data-testid="defense-provided-input" />
                <ComboboxControls>
                  <ComboboxClear />
                  <ComboboxTrigger />
                </ComboboxControls>
              </ComboboxField>
              <ComboboxContent emptyMessage={t_i18n('No available options')} listAriaLabel={t_i18n('Data components')} />
            </Combobox>
          </Box>
          <Button onClick={addSelected} disabled={adding || selected.length === 0} data-testid="defense-provided-add">
            {t_i18n('Add')}
          </Button>
        </Stack>
      </Security>
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
