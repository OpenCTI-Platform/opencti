import React from 'react';
import Grid from '@mui/material/Grid';
import { GenericAttackCardDummy } from '@components/common/cards/GenericAttackCard';
import {
  IntrusionSetsCardsPaginationQuery, IntrusionSetsCardsPaginationQuery$variables,
} from './intrusion_sets/__generated__/IntrusionSetsCardsPaginationQuery.graphql';
import ListCards from '../../../components/list_cards/ListCards';
import IntrusionSetsCards, { intrusionSetsCardsQuery } from './intrusion_sets/IntrusionSetsCards';
import IntrusionSetCreation from './intrusion_sets/IntrusionSetCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { Filters } from '../../../components/list_lines';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';

const LOCAL_STORAGE_KEY = 'view-intrusionSets';

const IntrusionSets = () => {
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<IntrusionSetsCardsPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      openExports: false,
      filters: {} as Filters,
    },
  );
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
    paginationOptions,
  );

  const renderCards = () => {
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
        exportEntityType="Intrusion-Set"
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

  return (
    <>
      {renderCards()}
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <IntrusionSetCreation paginationOptions={paginationOptions} />
      </Security>
    </>
  );
};

export default IntrusionSets;
