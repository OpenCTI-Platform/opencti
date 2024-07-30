import React from 'react';
import Grid from '@mui/material/Grid';
import { GenericAttackCardDummy } from '@components/common/cards/GenericAttackCard';
import {
  ThreatActorsGroupCardsPaginationQuery,
  ThreatActorsGroupCardsPaginationQuery$variables,
} from '@components/threats/threat_actors_group/__generated__/ThreatActorsGroupCardsPaginationQuery.graphql';
import { ThreatActorGroupCardFragment } from '@components/threats/threat_actors_group/ThreatActorGroupCard';
import { ThreatActorsGroupCards_data$data } from '@components/threats/threat_actors_group/__generated__/ThreatActorsGroupCards_data.graphql';
import Tooltip from '@mui/material/Tooltip';
import { ViewListOutlined, ViewModuleOutlined } from '@mui/icons-material';
import ToggleButton from '@mui/material/ToggleButton';
import ListCards from '../../../components/list_cards/ListCards';
import ThreatActorsGroupCards, { ThreatActorsGroupCardsFragment, threatActorsGroupCardsQuery } from './threat_actors_group/ThreatActorsGroupCards';
import ThreatActorGroupCreation from './threat_actors_group/ThreatActorGroupCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useHelper from '../../../utils/hooks/useHelper';

const LOCAL_STORAGE_KEY = 'threatActorsGroups';

const ThreatActorsGroup = () => {
  const { t_i18n } = useFormatter();
  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    view: 'cards',
  };
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<ThreatActorsGroupCardsPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const contextFilters = useBuildEntityTypeBasedFilterContext('Threat-Actor-Group', viewStorage.filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as ThreatActorsGroupCardsPaginationQuery$variables;

  const queryRef = useQueryLoading<ThreatActorsGroupCardsPaginationQuery>(
    threatActorsGroupCardsQuery,
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
        exportContext={{ entity_type: 'Threat-Actor-Group' }}
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        handleChangeView={helpers.handleChangeView}
        createButton={isFABReplaced && (
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <ThreatActorGroupCreation paginationOptions={queryPaginationOptions} />
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
            <ThreatActorsGroupCards
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
      linesQuery: threatActorsGroupCardsQuery,
      linesFragment: ThreatActorsGroupCardsFragment,
      queryRef,
      nodePath: ['threatActorsGroup', 'pageInfo', 'globalCount'],
      setNumberOfElements: helpers.handleSetNumberOfElements,
    } as UsePreloadedPaginationFragment<ThreatActorsGroupCardsPaginationQuery>;

    return (
      <>
        {queryRef && (
          <DataTable
            dataColumns={dataColumns}
            resolvePath={(data: ThreatActorsGroupCards_data$data) => data.threatActorsGroup?.edges?.map((n) => n?.node)}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            toolbarFilters={contextFilters}
            preloadedPaginationProps={preloadedPaginationProps}
            lineFragment={ThreatActorGroupCardFragment}
            exportContext={{ entity_type: 'Threat-Actor-Group' }}
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
                <ThreatActorGroupCreation paginationOptions={queryPaginationOptions} />
              </Security>
            )}
          />
        )}
      </>
    );
  };

  return (
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Threats') }, { label: t_i18n('Threat actors (group)'), current: true }]} />
      {viewStorage.view !== 'lines' ? renderCards() : renderList()}
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ThreatActorGroupCreation paginationOptions={queryPaginationOptions} />
        </Security>
      )}
    </>
  );
};

export default ThreatActorsGroup;
