import React from 'react';
import Grid from '@mui/material/Grid';
import { GenericAttackCardDummy } from '@components/common/cards/GenericAttackCard';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { ViewListOutlined, ViewModuleOutlined } from '@mui/icons-material';
import { IntrusionSetCardFragment } from '@components/threats/intrusion_sets/IntrusionSetCard';
import { IntrusionSetsCards_data$data } from '@components/threats/intrusion_sets/__generated__/IntrusionSetsCards_data.graphql';
import { IntrusionSetsCardsPaginationQuery, IntrusionSetsCardsPaginationQuery$variables } from './intrusion_sets/__generated__/IntrusionSetsCardsPaginationQuery.graphql';
import ListCards from '../../../components/list_cards/ListCards';
import IntrusionSetsCards, { intrusionSetsCardsFragment, intrusionSetsCardsQuery } from './intrusion_sets/IntrusionSetsCards';
import IntrusionSetCreation from './intrusion_sets/IntrusionSetCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../components/dataGrid/DataTable';
import useHelper from '../../../utils/hooks/useHelper';

const LOCAL_STORAGE_KEY = 'intrusionSets';

const IntrusionSets = () => {
  const { t_i18n } = useFormatter();
  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
    view: 'cards',
  };
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<IntrusionSetsCardsPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const contextFilters = useBuildEntityTypeBasedFilterContext('Intrusion-Set', viewStorage.filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as IntrusionSetsCardsPaginationQuery$variables;

  const {
    sortBy,
    orderAsc,
    searchTerm,
    filters,
    openExports,
    numberOfElements,
  } = viewStorage;

  const queryRef = useQueryLoading<IntrusionSetsCardsPaginationQuery>(
    intrusionSetsCardsQuery,
    queryPaginationOptions,
  );

  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const renderCards = () => {
    const dataColumns = {
      name: {
        label: 'Name',
      },
      created: {
        label: 'Original creation date',
      },
      modified: {
        label: 'Modification date',
      },
    };
    return (
      <ListCards
        helpers={helpers}
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        handleAddFilter={helpers.handleAddFilter}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
        handleSwitchLocalMode={helpers.handleSwitchLocalMode}
        handleToggleExports={helpers.handleToggleExports}
        openExports={openExports}
        exportContext={{ entity_type: 'Intrusion-Set' }}
        keyword={searchTerm}
        filters={filters}
        paginationOptions={queryPaginationOptions}
        numberOfElements={numberOfElements}
        handleChangeView={helpers.handleChangeView}
        createButton={isFABReplaced && (
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <IntrusionSetCreation paginationOptions={queryPaginationOptions} />
          </Security>
        )}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <Grid container={true} spacing={3} style={{ paddingLeft: 17 }}>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <Grid
                      item
                      xs={3}
                      key={idx}
                    >
                      <GenericAttackCardDummy />
                    </Grid>
                  ))}
              </Grid>
            }
          >
            <IntrusionSetsCards
              queryRef={queryRef}
              setNumberOfElements={helpers.handleSetNumberOfElements}
              onLabelClick={helpers.handleAddFilter}
            />
          </React.Suspense>
        )}
      </ListCards>
    );
  };

  const renderList = () => {
    const dataColumns = {
      name: {
        percentWidth: 15,
      },
      resource_level: {},
      primary_motivation: {},
      secondary_motivations: {},
      creator: {},
      modified: {},
      objectMarking: { percentWidth: 10 },
      objectLabel: {},
    };

    const preloadedPaginationProps = {
      linesQuery: intrusionSetsCardsQuery,
      linesFragment: intrusionSetsCardsFragment,
      queryRef,
      nodePath: ['intrusionSets', 'pageInfo', 'globalCount'],
      setNumberOfElements: helpers.handleSetNumberOfElements,
    } as UsePreloadedPaginationFragment<IntrusionSetsCardsPaginationQuery>;

    return (
      <>
        {queryRef && (
          <DataTable
            dataColumns={dataColumns}
            resolvePath={(data: IntrusionSetsCards_data$data) => data.intrusionSets?.edges?.map((n) => n?.node)}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            toolbarFilters={contextFilters}
            preloadedPaginationProps={preloadedPaginationProps}
            lineFragment={IntrusionSetCardFragment}
            exportContext={{ entity_type: 'Intrusion-Set' }}
            additionalHeaderButtons={[
              (<ToggleButton key="cards" value="cards" aria-label="cards">
                <Tooltip title={t_i18n('Cards view')}>
                  <ViewModuleOutlined fontSize="small" color="primary" />
                </Tooltip>
              </ToggleButton>),
              (<ToggleButton key="cards" value="lines" aria-label="lines">
                <Tooltip title={t_i18n('Lines view')}>
                  <ViewListOutlined color="primary" fontSize="small" />
                </Tooltip>
              </ToggleButton>),
            ]}
            createButton={isFABReplaced && (
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <IntrusionSetCreation paginationOptions={queryPaginationOptions} />
              </Security>
            )}
          />
        )}
      </>
    );
  };

  return (
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Threats') }, { label: t_i18n('Intrusion sets'), current: true }]} />
      {viewStorage.view !== 'lines' ? renderCards() : renderList()}
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <IntrusionSetCreation paginationOptions={queryPaginationOptions} />
        </Security>
      )}
    </>
  );
};

export default IntrusionSets;
