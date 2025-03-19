import React, { FunctionComponent } from 'react';
import { IncidentsLines_data$data } from '@components/events/incidents/__generated__/IncidentsLines_data.graphql';
import { incidentLineFragment } from '@components/events/incidents/IncidentLine';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { notificationsLinesFragment, notificationsLinesQuery } from './notifications/NotificationsLines';
import { NotificationsLinesPaginationQuery, NotificationsLinesPaginationQuery$variables } from './notifications/__generated__/NotificationsLinesPaginationQuery.graphql';
import useAuth from '../../../utils/hooks/useAuth';
import { emptyFilterGroup, isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../utils/filters/filtersUtils';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../components/dataGrid/DataTable';

export const LOCAL_STORAGE_KEY = 'notifiers';

const Notifications: FunctionComponent = () => {
  const { t_i18n } = useFormatter();

  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Notifications'));
  const {
    me,
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns: DataTableProps['dataColumns'] = {
    operation: {},
    message: {},
    created: {
      label: 'Original creation date',
      percentWidth: 20,
      isSortable: isRuntimeSort,
    },
    name: {
      label: 'Trigger name',
      percentWidth: 12,
      isSortable: isRuntimeSort,
    },
  };
  const initialValues = {
    filters: emptyFilterGroup,
    sortBy: 'created_at',
    orderAsc: false,
    openExports: false,
  };

  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<NotificationsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
    // {
    //   searchTerm: '',
    //   sortBy: 'created',
    //   orderAsc: false,
    //   filters: {
    //     ...emptyFilterGroup,
    //     filters: useGetDefaultFilterObject(['is_read', 'trigger_id'], ['Notification']),
    //   },
    //   numberOfElements: {
    //     number: 0,
    //     symbol: '',
    //   },
    // },
  );
  // const {
  //   filters,
  // } = viewStorage;
  // const contextFilters = useBuildEntityTypeBasedFilterContext('Notification', filters);

  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(viewStorage.filters, ['Notification']);
  const contextFilters = {
    mode: 'and',
    filters: [
      {
        key: 'entity_type',
        values: ['Notification'],
        operator: 'eq',
        mode: 'or',
      },
      {
        key: 'user_id',
        values: [me.id],
        operator: 'eq',
        mode: 'or',
      },
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as NotificationsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<NotificationsLinesPaginationQuery>(
    notificationsLinesQuery,
    queryPaginationOptions,
  );
  const preloadedPaginationProps = {
    linesQuery: notificationsLinesQuery,
    linesFragment: notificationsLinesFragment,
    queryRef,
    nodePath: ['notifiers', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<NotificationsLinesPaginationQuery>;
  return (
    <div>
      <Breadcrumbs elements={[{ label: t_i18n('Notifications'), current: true }]} />
      {queryRef && (
      <DataTable
        storageKey={LOCAL_STORAGE_KEY}
        initialValues={initialValues}
        preloadedPaginationProps={preloadedPaginationProps}
        resolvePath={(data: IncidentsLines_data$data) => data.incidents?.edges?.map((n) => n?.node)}
        dataColumns={dataColumns}
        lineFragment={incidentLineFragment}
        toolbarFilters={contextFilters}
        exportContext={{ entity_type: 'Notification' }}
        availableEntityTypes={['Notification']}
      />
      )}
    </div>

  // <ListLines
  //   helpers={helpers}
  //   sortBy={sortBy}
  //   orderAsc={orderAsc}
  //   dataColumns={dataColumns}
  //   handleSort={helpers.handleSort}
  //   handleSearch={helpers.handleSearch}
  //   handleAddFilter={helpers.handleAddFilter}
  //   handleRemoveFilter={helpers.handleRemoveFilter}
  //   handleSwitchFilter={helpers.handleSwitchFilter}
  //   handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
  //   handleSwitchLocalMode={helpers.handleSwitchLocalMode}
  //   handleToggleSelectAll={handleToggleSelectAll}
  //   selectAll={selectAll}
  //   keyword={searchTerm}
  //   filters={filters}
  //   iconExtension={true}
  //   secondaryAction={true}
  //   paginationOptions={queryPaginationOptions}
  //   numberOfElements={numberOfElements}
  //   entityTypes={['Notification']}
  // >
  //   {queryRef && (
  //   <React.Suspense
  //     fallback={
  //       <>
  //         {Array.from(Array(20).keys()).map((idx) => (
  //           <NotificationLineDummy
  //             key={`NotificationLineDummy-${idx}`}
  //             dataColumns={dataColumns}
  //           />
  //         ))}
  //       </>
  //                   }
  //   >
  //     <NotificationsLines
  //       queryRef={queryRef}
  //       paginationOptions={queryPaginationOptions}
  //       dataColumns={dataColumns}
  //       onLabelClick={helpers.handleAddFilter}
  //       setNumberOfElements={helpers.handleSetNumberOfElements}
  //       selectedElements={selectedElements}
  //       deSelectedElements={deSelectedElements}
  //       onToggleEntity={onToggleEntity}
  //       selectAll={selectAll}
  //     />
  //     <NotificationsToolBar
  //       selectedElements={selectedElements}
  //       deSelectedElements={deSelectedElements}
  //       numberOfSelectedElements={numberOfSelectedElements}
  //       handleClearSelectedElements={handleClearSelectedElements}
  //       selectAll={selectAll}
  //       filters={contextFilters}
  //     />
  //   </React.Suspense>
  //   )}
  // </ListLines>
  );
};

export default Notifications;
