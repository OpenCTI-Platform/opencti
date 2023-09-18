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
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';

const LOCAL_STORAGE_KEY = 'view-threatActorsGroups';

const ThreatActorsGroup = () => {
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<ThreatActorsGroupCardsPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      numberOfElements: {
        number: 0,
        symbol: '',
      },
      filters: {},
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
        label: 'Creation date',
      },
      modified: {
        label: 'Modification date',
      },
    };
    return (
      <ListCards
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        handleAddFilter={helpers.handleAddFilter}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleToggleExports={helpers.handleToggleExports}
        openExports={openExports}
        exportEntityType="Threat-Actor-Group"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'x_opencti_workflow_id',
          'labelledBy',
          'markedBy',
          'createdBy',
          'source_reliability',
          'confidence',
          'creator',
          'created_start_date',
          'created_end_date',
          'revoked',
          'targets',
        ]}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <Grid container={true} spacing={3} style={{ paddingLeft: 17 }}>
                {Array(20)
                  .fill(0)
                  .map((idx) => (
                    <Grid item={true} xs={3} key={idx}>
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
        {renderCards()}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ThreatActorGroupCreation paginationOptions={paginationOptions} />
        </Security>
      </>
  );
};

export default ThreatActorsGroup;
