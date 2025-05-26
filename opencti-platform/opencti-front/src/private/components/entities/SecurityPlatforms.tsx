import React from 'react';
import Grid from '@mui/material/Grid';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { ViewListOutlined, ViewModuleOutlined } from '@mui/icons-material';
import { ThreatActorIndividualCardFragment } from '@components/threats/threat_actors_individual/ThreatActorIndividualCard';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import ListCards from '../../../components/list_cards/ListCards';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { GenericAttackCardDummy } from '../common/cards/GenericAttackCard';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../components/dataGrid/DataTable';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

const LOCAL_STORAGE_KEY_SECURITY_PLATFORMS = 'securityPlatform';

const SecurityPlatforms = () => {
  const { t_i18n } = useFormatter();
  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    view: 'cards',
  };
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Security Platform'));
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<SecurityPlatformCardsPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_SECURITY_PLATFORMS,
    initialValues,
  );

  const contextFilters = useBuildEntityTypeBasedFilterContext('securityPlatform', viewStorage.filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as SecurityPlatformIndividualCardsPaginationQuery$variables;

  const queryRef = useQueryLoading<>(
    securityPlatformsCardsPaginationQuery,
    queryPaginationOptions,
  );

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
        exportContext={{ entity_type: 'securityPlatform' }}
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        handleChangeView={helpers.handleChangeView}
        // createButton={(
        //   <Security needs={[KNOWLEDGE_KNUPDATE]}>
        //     <SecurityPlatformsCreation paginationOptions={queryPaginationOptions} />
        //   </Security>
        // )}
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
            {/* <SecurityPlatformsCards */}
            {/*  queryRef={queryRef} */}
            {/*  setNumberOfElements={helpers.handleSetNumberOfElements} */}
            {/*  onLabelClick={helpers.handleAddFilter} */}
            {/* /> */}
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
      security_platform_types: {
        label: 'Type',
        percentWidth: 13,
      },
      sophistication: {},
      resource_level: {},
      creator: {},
      objectLabel: {},
      modified: {},
      objectMarking: { percentWidth: 10 },
    };

    const preloadedPaginationProps = {
      linesQuery: securityPlatformsCardsPaginationQuery,
      linesFragment: securityPlatformsCardsFragment,
      queryRef,
      nodePath: ['securityPlatforms', 'pageInfo', 'globalCount'],
      setNumberOfElements: helpers.handleSetNumberOfElements,
    } as UsePreloadedPaginationFragment<SecurityPlatformsCardsPaginationQuery>;

    return (
      <>
        {queryRef && (
          <DataTable
            dataColumns={dataColumns}
            resolvePath={(data: SecurityPlatformsCards_data$data) => data.securityPlatforms?.edges?.map((n) => n?.node)}
            storageKey={LOCAL_STORAGE_KEY_SECURITY_PLATFORMS}
            initialValues={initialValues}
            toolbarFilters={contextFilters}
            preloadedPaginationProps={preloadedPaginationProps}
            lineFragment={ThreatActorIndividualCardFragment}
            exportContext={{ entity_type: 'securityPlatform' }}
            additionalHeaderButtons={[
              (<ToggleButton key="cards" value="cards" aria-label="cards">
                <Tooltip title={t_i18n('Cards view')}>
                  <ViewModuleOutlined fontSize="small" color="primary" />
                </Tooltip>
              </ToggleButton>),
              (<ToggleButton key="lines" value="lines" aria-label="lines">
                <Tooltip title={t_i18n('Lines view')}>
                  <ViewListOutlined color="secondary" fontSize="small" />
                </Tooltip>
              </ToggleButton>),
            ]}
            // createButton={(
            //   <Security needs={[KNOWLEDGE_KNUPDATE]}>
            //     <SecurityPlatformsCreation paginationOptions={queryPaginationOptions} />
            //   </Security>
            // )}
          />
        )}
      </>
    );
  };

  return (
    <>
      <Breadcrumbs elements={[{ label: t_i18n('Security platforms') }, { label: t_i18n('Security Platforms'), current: true }]} />
      {viewStorage.view !== 'lines' ? renderCards() : renderList()}
    </>
  );
};

export default SecurityPlatforms;
