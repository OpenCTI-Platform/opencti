import React from 'react';
import Grid from '@mui/material/Grid';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { ViewListOutlined, ViewModuleOutlined } from '@mui/icons-material';
import { ThreatActorIndividualCardFragment } from '@components/threats/threat_actors_individual/ThreatActorIndividualCard';
import { ThreatActorsIndividualCards_data$data } from '@components/threats/threat_actors_individual/__generated__/ThreatActorsIndividualCards_data.graphql';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import ListCards from '../../../components/list_cards/ListCards';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import Security from '../../../utils/Security';
import { GenericAttackCardDummy } from '../common/cards/GenericAttackCard';
import ThreatActorsIndividualCards, {
  ThreatActorsIndividualCardsFragment,
  threatActorsIndividualCardsPaginationQuery,
} from './threat_actors_individual/ThreatActorsIndividualCards';
import {
  ThreatActorsIndividualCardsPaginationQuery,
  ThreatActorsIndividualCardsPaginationQuery$variables,
} from './threat_actors_individual/__generated__/ThreatActorsIndividualCardsPaginationQuery.graphql';
import ThreatActorIndividualCreation from './threat_actors_individual/ThreatActorIndividualCreation';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../components/dataGrid/DataTable';
import useHelper from '../../../utils/hooks/useHelper';

const LOCAL_STORAGE_KEY_THREAT_ACTORS_INDIVIDUAL = 'threatActorsIndividuals';

const ThreatActorsIndividual = () => {
  const { t_i18n } = useFormatter();
  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    view: 'cards',
  };
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<ThreatActorsIndividualCardsPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_THREAT_ACTORS_INDIVIDUAL,
    initialValues,
  );

  const contextFilters = useBuildEntityTypeBasedFilterContext('Threat-Actor-Individual', viewStorage.filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as ThreatActorsIndividualCardsPaginationQuery$variables;

  const queryRef = useQueryLoading<ThreatActorsIndividualCardsPaginationQuery>(
    threatActorsIndividualCardsPaginationQuery,
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
        exportContext={{ entity_type: 'Threat-Actor-Individual' }}
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        handleChangeView={helpers.handleChangeView}
        createButton={isFABReplaced && (
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <ThreatActorIndividualCreation paginationOptions={queryPaginationOptions} />
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
            <ThreatActorsIndividualCards
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
      threat_actor_types: {
        label: 'Type',
        percentWidth: 13,
      },
      sophistication: {},
      resource_level: {},
      creator: {},
      modified: {},
      objectMarking: { percentWidth: 10 },
      objectLabel: {},
    };

    const preloadedPaginationProps = {
      linesQuery: threatActorsIndividualCardsPaginationQuery,
      linesFragment: ThreatActorsIndividualCardsFragment,
      queryRef,
      nodePath: ['threatActorsIndividuals', 'pageInfo', 'globalCount'],
      setNumberOfElements: helpers.handleSetNumberOfElements,
    } as UsePreloadedPaginationFragment<ThreatActorsIndividualCardsPaginationQuery>;

    return (
      <>
        {queryRef && (
          <DataTable
            dataColumns={dataColumns}
            resolvePath={(data: ThreatActorsIndividualCards_data$data) => data.threatActorsIndividuals?.edges?.map((n) => n?.node)}
            storageKey={LOCAL_STORAGE_KEY_THREAT_ACTORS_INDIVIDUAL}
            initialValues={initialValues}
            toolbarFilters={contextFilters}
            preloadedPaginationProps={preloadedPaginationProps}
            lineFragment={ThreatActorIndividualCardFragment}
            exportContext={{ entity_type: 'Threat-Actor-Individual' }}
            additionalHeaderButtons={[
              (<ToggleButton key="cards" value="cards" aria-label="cards">
                <Tooltip title={t_i18n('Cards view')}>
                  <ViewModuleOutlined fontSize="small" color="primary" />
                </Tooltip>
              </ToggleButton>),
              (<ToggleButton key="lines" value="lines" aria-label="lines">
                <Tooltip title={t_i18n('Lines view')}>
                  <ViewListOutlined color="primary" fontSize="small" />
                </Tooltip>
              </ToggleButton>),
            ]}
            createButton={isFABReplaced && (
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <ThreatActorIndividualCreation paginationOptions={queryPaginationOptions} />
              </Security>
            )}
          />
        )}
      </>
    );
  };

  return (
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Threats') }, { label: t_i18n('Threat actors (individual)'), current: true }]} />
      {viewStorage.view !== 'lines' ? renderCards() : renderList()}
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ThreatActorIndividualCreation paginationOptions={queryPaginationOptions} />
        </Security>
      )}
    </>
  );
};

export default ThreatActorsIndividual;
