import React, { ReactNode, Suspense, useEffect, useRef, useState } from 'react';
import { graphql, useLazyLoadQuery, usePaginationFragment } from 'react-relay';
import { Chip, SearchField, Spinner, Text } from '@filigran/design-system';
import { ArrowBackOutlined } from '@mui/icons-material';
import Divider from '@mui/material/Divider';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import useDebounceCallback from '../../../../../utils/hooks/useDebounceCallback';
import { ConfigPresetImportItemsQuery } from './__generated__/ConfigPresetImportItemsQuery.graphql';
import { ConfigPresetImportItems_data$key } from './__generated__/ConfigPresetImportItems_data.graphql';
import { buildConfigPresetItemsFilter, clearConfigPresetTypeSelection, ConfigPresetSelection, countConfigPresetCheckedItems } from '../configPresetSelection';
import type { ConfigPresetForcedItems } from '../configPresetSelection';
import ConfigPresetStickyFooter from './ConfigPresetStickyFooter';

const PAGE_SIZE = 25;

// The filters of the list: the ones of the export, and the items that conflict with the platform (the ones the user may have to choose for)
type ConfigPresetImportItemsFilter = 'all' | 'selected' | 'excluded' | 'conflicts';

const configPresetImportItemsQuery = graphql`
  query ConfigPresetImportItemsQuery($file_id: ID!, $type: ID!, $count: Int!, $search: String, $ids: [ID!], $excludedIds: [ID!], $conflictsOnly: Boolean) {
    ...ConfigPresetImportItems_data @arguments(file_id: $file_id, type: $type, count: $count, search: $search, ids: $ids, excludedIds: $excludedIds, conflictsOnly: $conflictsOnly)
  }
`;

const configPresetImportItemsFragment = graphql`
  fragment ConfigPresetImportItems_data on Query
  @refetchable(queryName: "ConfigPresetImportItemsRefetchQuery")
  @argumentDefinitions(
    file_id: { type: "ID!" }
    type: { type: "ID!" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    search: { type: "String" }
    ids: { type: "[ID!]" }
    excludedIds: { type: "[ID!]" }
    conflictsOnly: { type: "Boolean" }
  ) {
    configPresetImportItems(file_id: $file_id, type: $type, first: $count, after: $cursor, search: $search, ids: $ids, excludedIds: $excludedIds, conflictsOnly: $conflictsOnly)
    @connection(key: "ConfigPresetImportItems_configPresetImportItems") {
      edges {
        node {
          key
          label
          translatable
          isDefault
          exists
          conflict
          isEnabled
          fields {
            key
            value
          }
          credentials {
            key
            description
            required
            stored
            secret
            type
          }
          dependsOn {
            type
            key
          }
          expected {
            status
            reason
            code
          }
        }
      }
    }
  }
`;

type ItemsVariables = Omit<ConfigPresetImportItemsQuery['variables'], 'count'>;

interface ConfigPresetImportItemsListProps<TItem> {
  variables: ItemsVariables;
  renderItem: (item: TItem) => ReactNode;
}

const ConfigPresetImportItemsList = <TItem, >({ variables, renderItem }: ConfigPresetImportItemsListProps<TItem>) => {
  const { t_i18n } = useFormatter();
  // The items are read again each time the sub-view opens: the platform may have changed since the preview
  const queryData = useLazyLoadQuery<ConfigPresetImportItemsQuery>(configPresetImportItemsQuery, { ...variables, count: PAGE_SIZE }, { fetchPolicy: 'network-only' });
  const { data, hasNext, isLoadingNext, loadNext } = usePaginationFragment<ConfigPresetImportItemsQuery, ConfigPresetImportItems_data$key>(
    configPresetImportItemsFragment,
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
  const edges = data.configPresetImportItems.edges;
  return (
    <>
      {edges.map(({ node }) => <React.Fragment key={node.key}>{renderItem(node as unknown as TItem)}</React.Fragment>)}
      {edges.length === 0 && <Text variant="content-base">{t_i18n('No results')}</Text>}
      <div ref={sentinelRef} />
      {isLoadingNext && <Spinner label={t_i18n('Loading')} />}
    </>
  );
};

interface ConfigPresetImportItemsProps<TItem> {
  fileId: string;
  type: {
    readonly key: string;
    readonly label: string;
    readonly itemsPageInfo: { readonly globalCount: number };
    // How many items of the type conflict with the platform
    readonly conflictsCount: number;
  };
  selection: ConfigPresetSelection;
  forced: ConfigPresetForcedItems;
  onSelectionChange: (selection: ConfigPresetSelection) => void;
  // The row of an item: its checkbox, its choice for an item that exists and its expected result, as in the main list
  renderItem: (item: TItem) => ReactNode;
  // Next to the filters: the choice for all the items that conflict
  typeActions?: ReactNode;
  onBack: () => void;
}

// Sub-view of the preview for a type with more items than its first page: search, filters, infinite scroll, and what the user chooses for
// the items that already exist. The pages come from the API, which reads what the preview computed: a bundle of tens of thousands of items
// is never sent or mounted at once.
const ConfigPresetImportItems = <TItem, >({
  fileId,
  type,
  selection,
  forced,
  onSelectionChange,
  renderItem,
  typeActions,
  onBack,
}: ConfigPresetImportItemsProps<TItem>) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [searchInput, setSearchInput] = useState('');
  // The list arguments are computed when the search or the filter changes, not on every check: the list stays in place
  const [query, setQuery] = useState<{ search: string; filter: ConfigPresetImportItemsFilter }>({ search: '', filter: 'all' });
  const [variables, setVariables] = useState<ItemsVariables>({ file_id: fileId, type: type.key, search: '' });
  const applyQuery = (search: string, filter: ConfigPresetImportItemsFilter) => {
    setQuery({ search, filter });
    setVariables({
      file_id: fileId,
      type: type.key,
      search,
      ...(filter === 'conflicts' ? { conflictsOnly: true } : buildConfigPresetItemsFilter(selection, forced, type.key, filter)),
    });
  };
  const debouncedSearch = useDebounceCallback((search: string) => applyQuery(search, query.filter), 300);
  const total = type.itemsPageInfo.globalCount;
  const selected = countConfigPresetCheckedItems([type], selection, forced);
  const filters: { id: ConfigPresetImportItemsFilter; label: string; count: number }[] = [
    { id: 'all', label: t_i18n('All'), count: total },
    { id: 'selected', label: t_i18n('Selected'), count: selected },
    { id: 'excluded', label: t_i18n('Excluded'), count: total - selected },
    ...(type.conflictsCount > 0 ? [{ id: 'conflicts' as const, label: t_i18n('Already exists'), count: type.conflictsCount }] : []),
  ];
  return (
    <>
      <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5) }}>
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
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: theme.spacing(1) }}>
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
          {typeActions}
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
      <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5) }}>
        <Suspense fallback={<Spinner label={t_i18n('Loading')} />}>
          <ConfigPresetImportItemsList key={JSON.stringify(variables)} variables={variables} renderItem={renderItem} />
        </Suspense>
      </div>
      {/* Not the last row of the list: each page that loads would push it down */}
      <ConfigPresetStickyFooter hasBorder>
        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <Button startIcon={<ArrowBackOutlined />} onClick={onBack}>
            {t_i18n('Back to bundle')}
          </Button>
        </div>
      </ConfigPresetStickyFooter>
    </>
  );
};

export default ConfigPresetImportItems;
