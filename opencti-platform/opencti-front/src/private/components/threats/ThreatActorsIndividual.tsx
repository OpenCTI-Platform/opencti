import React from 'react';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import ListCards from '../../../components/list_cards/ListCards';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import Security from '../../../utils/Security';
import { ThreatActorIndividualCardDummy } from './threat_actors_individual/ThreatActorIndividualCard';
import ThreatActorsIndividualCards, {
  threatActorsIndividualCardsPaginationQuery,
} from './threat_actors_individual/ThreatActorsIndividualCards';
import {
  ThreatActorsIndividualCardsPaginationQuery,
  ThreatActorsIndividualCardsPaginationQuery$variables,
} from './threat_actors_individual/__generated__/ThreatActorsIndividualCardsPaginationQuery.graphql';
import ThreatActorIndividualCreation from './threat_actors_individual/ThreatActorIndividualCreation';

const LOCAL_STORAGE_KEY_THREAT_ACTORS_INDIVIDUAL = 'view-threatActorsIndividuals';

const ThreatActorsIndividual = () => {
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<ThreatActorsIndividualCardsPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_THREAT_ACTORS_INDIVIDUAL,
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

  const queryRef = useQueryLoading<ThreatActorsIndividualCardsPaginationQuery>(
    threatActorsIndividualCardsPaginationQuery,
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
        exportEntityType="Threat-Actor-Individual"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        availableFilterKeys={[
          'labelledBy',
          'markedBy',
          'created_start_date',
          'created_end_date',
          'createdBy',
          'creator',
          'revoked',
          'confidence',
        ]}
      >
        {queryRef && (
          <React.Suspense
            fallback={
            <>
              {Array(20)
                .fill(0)
                .map((idx) => (
                  <ThreatActorIndividualCardDummy
                    key={idx}
                  />
                ))}
            </>
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
  return (
    <div>
      {renderCards()}
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <ThreatActorIndividualCreation paginationOptions={paginationOptions} />
      </Security>
    </div>
  );
};

export default ThreatActorsIndividual;
