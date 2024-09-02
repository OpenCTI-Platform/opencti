import React from 'react';
import Grid from '@mui/material/Grid';
import { GenericAttackCardDummy } from '@components/common/cards/GenericAttackCard';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { ViewListOutlined, ViewModuleOutlined } from '@mui/icons-material';
import { CampaignsCards_data$data } from '@components/threats/campaigns/__generated__/CampaignsCards_data.graphql';
import { CampaignCardFragment } from '@components/threats/campaigns/CampaignCard';
import { CampaignsCardsPaginationQuery, CampaignsCardsPaginationQuery$variables } from './campaigns/__generated__/CampaignsCardsPaginationQuery.graphql';
import ListCards from '../../../components/list_cards/ListCards';
import CampaignsCards, { campaignsCardsFragment, campaignsCardsQuery } from './campaigns/CampaignsCards';
import CampaignCreation from './campaigns/CampaignCreation';
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

const LOCAL_STORAGE_KEY = 'campaigns';

const Campaigns = () => {
  const { t_i18n } = useFormatter();
  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    view: 'cards',
  };
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<CampaignsCardsPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const contextFilters = useBuildEntityTypeBasedFilterContext('Campaign', viewStorage.filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as CampaignsCardsPaginationQuery$variables;

  const queryRef = useQueryLoading<CampaignsCardsPaginationQuery>(
    campaignsCardsQuery,
    queryPaginationOptions,
  );

  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const renderCards = () => {
    const {
      numberOfElements,
      filters,
      searchTerm,
      sortBy,
      orderAsc,
      openExports,
    } = viewStorage;
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
        exportContext={{ entity_type: 'Campaign' }}
        keyword={searchTerm}
        filters={filters}
        paginationOptions={queryPaginationOptions}
        numberOfElements={numberOfElements}
        handleChangeView={helpers.handleChangeView}
        createButton={isFABReplaced && (
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <CampaignCreation paginationOptions={queryPaginationOptions} />
          </Security>
        )}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <Grid
                container={true}
                spacing={3}
                style={{ paddingLeft: 17 }}
              >
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
            <CampaignsCards
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
      creator: {},
      created: {
        percentWidth: 10,
      },
      modified: {},
      createdBy: {},
      objectMarking: { percentWidth: 10 },
      objectLabel: {},
      x_opencti_workflow_id: {
        label: 'Processing status',
        percentWidth: 10,
      },
    };

    const preloadedPaginationProps = {
      linesQuery: campaignsCardsQuery,
      linesFragment: campaignsCardsFragment,
      queryRef,
      nodePath: ['campaigns', 'pageInfo', 'globalCount'],
      setNumberOfElements: helpers.handleSetNumberOfElements,
    } as UsePreloadedPaginationFragment<CampaignsCardsPaginationQuery>;

    return (
      <>
        {queryRef && (
          <DataTable
            dataColumns={dataColumns}
            resolvePath={(data: CampaignsCards_data$data) => data.campaigns?.edges?.map((n) => n?.node)}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            toolbarFilters={contextFilters}
            preloadedPaginationProps={preloadedPaginationProps}
            lineFragment={CampaignCardFragment}
            exportContext={{ entity_type: 'Campaign' }}
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
                <CampaignCreation paginationOptions={queryPaginationOptions} />
              </Security>
            )}
          />
        )}
      </>
    );
  };

  return (
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Threats') }, { label: t_i18n('Campaigns'), current: true }]} />
      {viewStorage.view !== 'lines' ? renderCards() : renderList()}
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <CampaignCreation paginationOptions={queryPaginationOptions} />
        </Security>
      )}
    </>
  );
};

export default Campaigns;
