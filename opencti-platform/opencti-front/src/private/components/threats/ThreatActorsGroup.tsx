import React from 'react';
import Grid from '@mui/material/Grid';
import { GenericAttackCardDummy } from '@components/common/cards/GenericAttackCard';
import {
  ThreatActorsGroupCardsPaginationQuery,
  ThreatActorsGroupCardsPaginationQuery$variables,
} from '@components/threats/threat_actors_group/__generated__/ThreatActorsGroupCardsPaginationQuery.graphql';
import ListCards from '../../../components/list_cards/ListCards';
import ThreatActorsGroupCards, { threatActorsGroupCardsQuery } from './threat_actors_group/ThreatActorsGroupCards';
import ThreatActorGroupCreation from './threat_actors_group/ThreatActorGroupCreation';
import { KnowledgeSecurity } from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';

const LOCAL_STORAGE_KEY = 'threatActorsGroups';

const ThreatActorsGroup = () => {
  const { t_i18n } = useFormatter();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<ThreatActorsGroupCardsPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      numberOfElements: {
        number: 0,
        symbol: '',
      },
      filters: emptyFilterGroup,
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      openExports: false,
      view: 'cards',
    },
  );
  const queryRef = useQueryLoading<ThreatActorsGroupCardsPaginationQuery>(
    threatActorsGroupCardsQuery,
    paginationOptions,
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
        exportContext={{ entity_type: 'Threat-Actor-Group' }}
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <Grid container={true} spacing={3} style={{ paddingLeft: 17 }}>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <Grid
                      item={true}
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

  return (
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Threats') }, { label: t_i18n('Threat actors (group)'), current: true }]} />
      {renderCards()}
      <KnowledgeSecurity needs={[KNOWLEDGE_KNUPDATE]} entity='Threat-Actor-Group'>
        <ThreatActorGroupCreation paginationOptions={paginationOptions} />
      </KnowledgeSecurity>
    </>
  );
};

export default ThreatActorsGroup;
