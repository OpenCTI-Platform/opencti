import React, { Suspense, useState } from 'react';
import { useNavigate } from 'react-router';
import { Chip, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { DeleteOutlined } from '@mui/icons-material';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import Loader, { LoaderVariant } from '../../../components/Loader';
import DataTable from '../../../components/dataGrid/DataTable';
import type { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import ListCards from '../../../components/list_cards/ListCards';
import ViewSwitchingButtons from '../../../components/ViewSwitchingButtons';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import IntelligenceRequirementsStats from './IntelligenceRequirementsStats';
import IntelligenceRequirementsCards, {
  intelligenceRequirementLineFragment,
  intelligenceRequirementsLinesFragment,
  intelligenceRequirementsLinesQuery,
  PRIORITY_SEVERITY,
} from './IntelligenceRequirementsCards';
import IrSparkline from './IrSparkline';
import IrAiAssistedCreation from './IrAiAssistedCreation';
import IrDeleteDialog from './IrDeleteDialog';
import { deleteNode } from '../../../utils/store';
import type { IntelligenceRequirementsLinesQuery, IntelligenceRequirementsLinesQuery$variables } from './__generated__/IntelligenceRequirementsLinesQuery.graphql';
import type { IntelligenceRequirements_data$data } from './__generated__/IntelligenceRequirements_data.graphql';
import type { IntelligenceRequirementsLine_node$data } from './__generated__/IntelligenceRequirementsLine_node.graphql';

const LOCAL_STORAGE_KEY = 'intelligenceRequirements';
const ENTITY_TYPE = 'IntelligenceRequirement';

const IntelligenceRequirements = () => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('PIR (generic)'));
  const initialValues = {
    searchTerm: '',
    sortBy: 'created_at',
    orderAsc: false,
    openExports: false,
    filters: emptyFilterGroup,
    view: 'lines',
  };
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<IntelligenceRequirementsLinesQuery$variables>(LOCAL_STORAGE_KEY, initialValues);
  const contextFilters = useBuildEntityTypeBasedFilterContext(ENTITY_TYPE, viewStorage.filters);
  const queryPaginationOptions = { ...paginationOptions, filters: contextFilters } as unknown as IntelligenceRequirementsLinesQuery$variables;
  const queryRef = useQueryLoading<IntelligenceRequirementsLinesQuery>(intelligenceRequirementsLinesQuery, queryPaginationOptions);
  const [toDelete, setToDelete] = useState<{ id: string; name: string } | null>(null);

  const createButton = (
    <Box sx={{ display: 'flex', gap: 1 }}>
      <IrAiAssistedCreation />
      <Button onClick={() => navigate('/dashboard/intelligence_requirements/new')}>{t_i18n('Create a requirement')}</Button>
    </Box>
  );
  const viewButtons = [
    <ViewSwitchingButtons key="switching_buttons" handleChangeView={helpers.handleChangeView} currentView={viewStorage.view} />,
  ];

  const renderList = () => {
    const dataColumns: DataTableProps['dataColumns'] = {
      name: { percentWidth: 26 },
      ir_priority: {
        id: 'ir_priority',
        label: 'Priority',
        percentWidth: 9,
        isSortable: false, // stored as text: an alphabetical sort would put high before critical
        render: ({ ir_priority }: IntelligenceRequirementsLine_node$data) => <Chip label={t_i18n(ir_priority)} severity={PRIORITY_SEVERITY[ir_priority]} />,
      },
      ir_status: {
        id: 'ir_status',
        label: 'Status',
        percentWidth: 8,
        isSortable: false,
        render: ({ ir_status }: IntelligenceRequirementsLine_node$data) => <Chip label={t_i18n(ir_status === 'active' ? 'Active' : 'Paused')} />,
      },
      ir_entities_count: {
        id: 'ir_entities_count',
        label: 'Entities',
        percentWidth: 8,
        isSortable: false,
        render: ({ ir_entities_count }: IntelligenceRequirementsLine_node$data) => <Text as="span" variant="content-compact-medium">{String(ir_entities_count)}</Text>,
      },
      ir_inbox_open_count: {
        id: 'ir_inbox_open_count',
        label: 'Inbox',
        percentWidth: 8,
        isSortable: false,
        render: ({ ir_inbox_open_count }: IntelligenceRequirementsLine_node$data) => <Text as="span" variant="content-compact-medium">{String(ir_inbox_open_count)}</Text>,
      },
      ir_activity: {
        id: 'ir_activity',
        label: 'Activity (7 days)',
        percentWidth: 14,
        isSortable: false,
        render: ({ ir_activity }: IntelligenceRequirementsLine_node$data) => <IrSparkline points={ir_activity} width={120} height={28} />,
      },
      creator: { percentWidth: 12 },
      created_at: { percentWidth: 15 },
    };
    return queryRef && (
      <DataTable
        removeSelectAll
        disableLineSelection
        dataColumns={dataColumns}
        resolvePath={(data: IntelligenceRequirements_data$data) => data.intelligenceRequirements?.edges?.map((e) => e?.node)}
        storageKey={LOCAL_STORAGE_KEY}
        initialValues={initialValues}
        contextFilters={contextFilters}
        preloadedPaginationProps={{
          linesQuery: intelligenceRequirementsLinesQuery,
          linesFragment: intelligenceRequirementsLinesFragment,
          queryRef,
          nodePath: ['intelligenceRequirements', 'pageInfo', 'globalCount'],
          setNumberOfElements: helpers.handleSetNumberOfElements,
        }}
        lineFragment={intelligenceRequirementLineFragment}
        entityTypes={[ENTITY_TYPE]}
        searchContextFinal={{ entityTypes: [ENTITY_TYPE] }}
        additionalHeaderToggleButtons={viewButtons}
        createButton={createButton}
        actions={(row: IntelligenceRequirementsLine_node$data) => (
          <IconButton
            aria-label={t_i18n('Delete')}
            onClick={(e: React.MouseEvent) => {
              e.stopPropagation();
              setToDelete({ id: row.id, name: row.name });
            }}
          >
            <DeleteOutlined fontSize="small" />
          </IconButton>
        )}
      />
    );
  };

  const renderCards = () => (
    <ListCards
      helpers={helpers}
      sortBy={viewStorage.sortBy}
      orderAsc={viewStorage.orderAsc}
      dataColumns={{ name: { label: 'Name' }, created_at: { label: 'Creation date' } }}
      handleSort={helpers.handleSort}
      handleSearch={helpers.handleSearch}
      handleAddFilter={helpers.handleAddFilter}
      handleRemoveFilter={helpers.handleRemoveFilter}
      handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
      handleSwitchLocalMode={helpers.handleSwitchLocalMode}
      handleChangeView={helpers.handleChangeView}
      keyword={viewStorage.searchTerm}
      filters={viewStorage.filters}
      paginationOptions={queryPaginationOptions}
      numberOfElements={viewStorage.numberOfElements}
      createButton={createButton}
    >
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <IntelligenceRequirementsCards queryRef={queryRef} setNumberOfElements={helpers.handleSetNumberOfElements} />
        </Suspense>
      )}
    </ListCards>
  );

  return (
    <>
      <Breadcrumbs elements={[{ label: t_i18n('PIR (generic)'), current: true }]} />
      <Suspense fallback={<Box sx={{ height: 190 }}><Loader variant={LoaderVariant.inElement} /></Box>}>
        <IntelligenceRequirementsStats />
      </Suspense>
      {viewStorage.view === 'cards' ? renderCards() : renderList()}
      <IrDeleteDialog
        ir={toDelete}
        onClose={() => setToDelete(null)}
        onDeleted={() => {}}
        updater={(store) => toDelete && deleteNode(store, 'Pagination_intelligenceRequirements', queryPaginationOptions, toDelete.id)}
      />
    </>
  );
};

export default IntelligenceRequirements;
