import React, { FunctionComponent } from 'react';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import ListLines from '../../../components/list_lines/ListLines';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import NotificationsLines, { notificationsLinesQuery } from './notifications/NotificationsLines';
import { NotificationsLinesPaginationQuery, NotificationsLinesPaginationQuery$variables } from './notifications/__generated__/NotificationsLinesPaginationQuery.graphql';
import { NotificationLineDummy } from './notifications/NotificationLine';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import { NotificationLine_node$data } from './notifications/__generated__/NotificationLine_node.graphql';
import useAuth from '../../../utils/hooks/useAuth';
import NotificationsToolBar from './notifications/NotificationsToolBar';
import { emptyFilterGroup, useGetDefaultFilterObject, isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../utils/filters/filtersUtils';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';

export const LOCAL_STORAGE_KEY = 'notifiers';

const Notifications: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { me } = useAuth();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<NotificationsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'created',
      orderAsc: false,
      filters: {
        ...emptyFilterGroup,
        filters: useGetDefaultFilterObject(['is_read'], ['Notification']),
      },
      numberOfElements: {
        number: 0,
        symbol: '',
      },
    },
  );
  const {
    onToggleEntity,
    numberOfSelectedElements,
    handleClearSelectedElements,
    selectedElements,
    deSelectedElements,
    handleToggleSelectAll,
    selectAll,
  } = useEntityToggle<NotificationLine_node$data>(
    LOCAL_STORAGE_KEY,
  );
  const renderLines = () => {
    const { searchTerm, sortBy, orderAsc, filters, numberOfElements } = viewStorage;
    const dataColumns = {
      operation: {
        label: 'Operation',
        width: '10%',
        isSortable: false,
      },
      message: {
        label: 'Message',
        width: '45%',
        isSortable: false,
      },
      created: {
        label: 'Original creation date',
        width: '15%',
        isSortable: true,
      },
      name: {
        label: 'Trigger',
        width: '15%',
        isSortable: true,
      },
    };

    const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['Notification']);
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

    return (
      <ListLines
        helpers={helpers}
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        handleAddFilter={helpers.handleAddFilter}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleSwitchFilter={helpers.handleSwitchFilter}
        handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
        handleSwitchLocalMode={helpers.handleSwitchLocalMode}
        handleToggleSelectAll={handleToggleSelectAll}
        selectAll={selectAll}
        keyword={searchTerm}
        filters={filters}
        iconExtension={true}
        secondaryAction={true}
        paginationOptions={queryPaginationOptions}
        numberOfElements={numberOfElements}
        entityTypes={['Notification']}
      >
        {queryRef && (
        <React.Suspense
          fallback={
            <>
              {Array.from(Array(20).keys()).map((idx) => (
                <NotificationLineDummy
                  key={`NotificationLineDummy-${idx}`}
                  dataColumns={dataColumns}
                />
              ))}
            </>
                        }
        >
          <NotificationsLines
            queryRef={queryRef}
            paginationOptions={queryPaginationOptions}
            dataColumns={dataColumns}
            onLabelClick={helpers.handleAddFilter}
            setNumberOfElements={helpers.handleSetNumberOfElements}
            selectedElements={selectedElements}
            deSelectedElements={deSelectedElements}
            onToggleEntity={onToggleEntity}
            selectAll={selectAll}
          />
          <NotificationsToolBar
            selectedElements={selectedElements}
            deSelectedElements={deSelectedElements}
            numberOfSelectedElements={numberOfSelectedElements}
            handleClearSelectedElements={handleClearSelectedElements}
            selectAll={selectAll}
            filters={contextFilters}
          />
        </React.Suspense>
        )}
      </ListLines>
    );
  };
  return (
    <>
      <Breadcrumbs elements={[{ label: t_i18n('Notifications'), current: true }]} />
      {renderLines()}
    </>
  );
};

export default Notifications;
