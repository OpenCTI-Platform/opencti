import React, { FunctionComponent, Suspense, useEffect, useRef, useState } from 'react';
import { graphql, useLazyLoadQuery, usePaginationFragment } from 'react-relay';
import { Checkbox, Chip, SearchField, Spinner, Text } from '@filigran/design-system';
import { ArrowBackOutlined } from '@mui/icons-material';
import Divider from '@mui/material/Divider';
import { useTheme } from '@mui/styles';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useDebounceCallback from '../../../../utils/hooks/useDebounceCallback';
import { ConfigPresetExportItemsQuery } from './__generated__/ConfigPresetExportItemsQuery.graphql';
import { ConfigPresetExportItems_data$key } from './__generated__/ConfigPresetExportItems_data.graphql';
import {
  buildConfigPresetItemsFilter,
  clearConfigPresetTypeSelection,
  ConfigPresetForcedItems,
  ConfigPresetItemsFilter,
  ConfigPresetSelection,
  countConfigPresetCheckedItems,
  isConfigPresetItemSelected,
  toggleConfigPresetItem,
} from './configPresetSelection';

const PAGE_SIZE = 25;

const configPresetExportItemsQuery = graphql`
  query ConfigPresetExportItemsQuery($type: ID!, $count: Int!, $search: String, $ids: [ID!], $excludedIds: [ID!]) {
    ...ConfigPresetExportItems_data @arguments(type: $type, count: $count, search: $search, ids: $ids, excludedIds: $excludedIds)
  }
`;

const configPresetExportItemsFragment = graphql`
  fragment ConfigPresetExportItems_data on Query
  @refetchable(queryName: "ConfigPresetExportItemsRefetchQuery")
  @argumentDefinitions(
    type: { type: "ID!" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    search: { type: "String" }
    ids: { type: "[ID!]" }
    excludedIds: { type: "[ID!]" }
  ) {
    configPresetExportableItems(type: $type, first: $count, after: $cursor, search: $search, ids: $ids, excludedIds: $excludedIds)
    @connection(key: "ConfigPresetExportItems_configPresetExportableItems") {
      edges {
        node {
          key
          label
          translatable
          isDefault
        }
      }
    }
  }
`;

interface ConfigPresetItem {
  readonly key: string;
  readonly label: string;
  readonly translatable: boolean;
  readonly isDefault: boolean;
}

interface ConfigPresetSelectionProps {
  selection: ConfigPresetSelection;
  forced: ConfigPresetForcedItems;
  onSelectionChange: (selection: ConfigPresetSelection) => void;
}

// A forced dependency is checked and disabled
export const ConfigPresetItemRow: FunctionComponent<ConfigPresetSelectionProps & { typeKey: string; item: ConfigPresetItem }> = ({
  typeKey,
  item,
  selection,
  forced,
  onSelectionChange,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const isForced = (forced[typeKey] ?? []).includes(item.key);
  const tags = item.isDefault ? [t_i18n('default')] : [];
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: theme.spacing(1) }}>
      <Checkbox
        label={item.translatable ? t_i18n(item.label) : item.label}
        checked={isForced || isConfigPresetItemSelected(selection, typeKey, item.key)}
        disabled={isForced}
        onCheckedChange={(checked) => onSelectionChange(toggleConfigPresetItem(selection, typeKey, item.key, checked === true))}
      />
      {tags.length > 0 && (
        <Text variant="content-compact" style={{ color: theme.palette.text.secondary }}>{tags.join(' · ')}</Text>
      )}
    </div>
  );
};

type ItemsVariables = Omit<ConfigPresetExportItemsQuery['variables'], 'count'>;

const ConfigPresetExportItemsList: FunctionComponent<ConfigPresetSelectionProps & { variables: ItemsVariables }> = ({ variables, ...rowProps }) => {
  const { t_i18n } = useFormatter();
  const queryData = useLazyLoadQuery<ConfigPresetExportItemsQuery>(configPresetExportItemsQuery, { ...variables, count: PAGE_SIZE });
  const { data, hasNext, isLoadingNext, loadNext } = usePaginationFragment<ConfigPresetExportItemsQuery, ConfigPresetExportItems_data$key>(
    configPresetExportItemsFragment,
    queryData,
  );
  const sentinelRef = useRef<HTMLDivElement | null>(null);
  // Infinite scroll: the next page loads when the end of the list comes into view
  useEffect(() => {
    const sentinel = sentinelRef.current;
    if (!sentinel || !hasNext || isLoadingNext) return undefined;
    const observer = new IntersectionObserver((entries) => {
      if (entries.some((entry) => entry.isIntersecting)) {
        loadNext(PAGE_SIZE);
      }
    }, { rootMargin: '200px' });
    observer.observe(sentinel);
    return () => observer.disconnect();
  }, [hasNext, isLoadingNext, loadNext]);
  const edges = data.configPresetExportableItems.edges;
  return (
    <>
      {edges.map(({ node }) => <ConfigPresetItemRow key={node.key} typeKey={variables.type} item={node} {...rowProps} />)}
      {edges.length === 0 && <Text variant="content-base">{t_i18n('No results')}</Text>}
      <div ref={sentinelRef} />
      {isLoadingNext && <Spinner label={t_i18n('Loading')} />}
    </>
  );
};

interface ConfigPresetExportItemsProps extends ConfigPresetSelectionProps {
  type: {
    readonly key: string;
    readonly label: string;
    readonly itemsPageInfo: { readonly globalCount: number };
  };
  onBack: () => void;
}

// Sub-view of the drawer for a type with more items than its first page: search, filters, infinite scroll
const ConfigPresetExportItems: FunctionComponent<ConfigPresetExportItemsProps> = ({ type, selection, forced, onSelectionChange, onBack }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [searchInput, setSearchInput] = useState('');
  // The list arguments are computed when the search or the filter changes, not on every check: the list stays in place
  const [query, setQuery] = useState<{ search: string; filter: ConfigPresetItemsFilter }>({ search: '', filter: 'all' });
  const [variables, setVariables] = useState<ItemsVariables>({ type: type.key, search: '' });
  const applyQuery = (search: string, filter: ConfigPresetItemsFilter) => {
    setQuery({ search, filter });
    setVariables({ type: type.key, search, ...buildConfigPresetItemsFilter(selection, forced, type.key, filter) });
  };
  const debouncedSearch = useDebounceCallback((search: string) => applyQuery(search, query.filter), 300);
  const total = type.itemsPageInfo.globalCount;
  const selected = countConfigPresetCheckedItems([type], selection, forced);
  const rowProps = { selection, forced, onSelectionChange };
  const filters: { id: ConfigPresetItemsFilter; label: string; count: number }[] = [
    { id: 'all', label: t_i18n('All'), count: total },
    { id: 'selected', label: t_i18n('Selected'), count: selected },
    { id: 'excluded', label: t_i18n('Excluded'), count: total - selected },
  ];
  return (
    <>
      <div style={{ padding: theme.spacing(3, 3, 2), display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5) }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
          <IconButton aria-label={t_i18n('Back')} onClick={onBack}>
            <ArrowBackOutlined />
          </IconButton>
          <Text variant="title-sm">{t_i18n(type.label)}</Text>
          <Text variant="content-base">{t_i18n('{selected} / {total} selected', { values: { selected, total } })}</Text>
        </div>
        <SearchField
          aria-label={t_i18n('Search')}
          placeholder={t_i18n('Search')}
          value={searchInput}
          onChange={(event) => {
            setSearchInput(event.target.value);
            debouncedSearch(event.target.value);
          }}
          onClear={() => {
            setSearchInput('');
            debouncedSearch.cancel();
            applyQuery('', query.filter);
          }}
        />
        <div style={{ display: 'flex', gap: theme.spacing(1) }}>
          {filters.map((filter) => (
            <Chip
              key={filter.id}
              label={`${filter.label} ${filter.count}`}
              severity={query.filter === filter.id ? 'info' : 'neutral'}
              aria-pressed={query.filter === filter.id}
              onClick={() => {
                // A search still waiting for its delay is applied now, with the new filter
                debouncedSearch.cancel();
                applyQuery(searchInput, filter.id);
              }}
            />
          ))}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: theme.spacing(1, 2), borderRadius: 4, border: `1px solid ${theme.palette.divider}` }}>
          <Text variant="content-base">
            {selected === total
              ? t_i18n('All {total} selected', { values: { total } })
              : t_i18n('{selected} selected, {excluded} excluded', { values: { selected, excluded: total - selected } })}
          </Text>
          <Button variant="tertiary" onClick={() => onSelectionChange(clearConfigPresetTypeSelection(selection, type.key))}>
            {t_i18n('Clear selection')}
          </Button>
        </div>
      </div>
      <Divider />
      <div style={{ flexGrow: 1, overflowY: 'auto', padding: theme.spacing(2, 3), display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5) }}>
        <Suspense fallback={<Spinner label={t_i18n('Loading')} />}>
          <ConfigPresetExportItemsList key={JSON.stringify(variables)} variables={variables} {...rowProps} />
        </Suspense>
      </div>
      <Divider />
      <div style={{ display: 'flex', justifyContent: 'flex-end', padding: theme.spacing(3) }}>
        <Button startIcon={<ArrowBackOutlined />} onClick={onBack}>
          {t_i18n('Back to bundle')}
        </Button>
      </div>
    </>
  );
};

export default ConfigPresetExportItems;
