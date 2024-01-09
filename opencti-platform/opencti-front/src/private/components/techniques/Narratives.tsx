import React from 'react';
import { NarrativesLinesPaginationQuery, NarrativesLinesPaginationQuery$variables } from '@components/techniques/narratives/__generated__/NarrativesLinesPaginationQuery.graphql';
import { NarrativeLine } from '@components/techniques/narratives/NarrativeLine';
import NarrativesLines, { narrativesLinesQuery } from './narratives/NarrativesLines';
import NarrativeCreation from './narratives/NarrativeCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import ListLines from '../../../components/list_lines/ListLines';

const LOCAL_STORAGE_KEY = 'narratives';

const Narratives = () => {
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<NarrativesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      openExports: false,
      filters: emptyFilterGroup,
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
  const dataColumns = {
    killChainPhase: {
      label: 'Kill chain phase',
      width: '15%',
      isSortable: false,
    },
    x_mitre_id: {
      label: 'ID',
      width: '10%',
      isSortable: true,
    },
    name: {
      label: 'Name',
      width: '30%',
      isSortable: true,
    },
    objectLabel: {
      label: 'Labels',
      width: '20%',
      isSortable: false,
    },
    created: {
      label: 'Creation date',
      width: '10%',
      isSortable: true,
    },
    modified: {
      label: 'Modification date',
      width: '10%',
      isSortable: true,
    },
  };
  const queryRef = useQueryLoading<NarrativesLinesPaginationQuery>(
    narrativesLinesQuery,
    paginationOptions,
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
      handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
      handleSwitchLocalMode={helpers.handleSwitchLocalMode}
      handleToggleExports={helpers.handleToggleExports}
      openExports={openExports}
      exportEntityType="Narrative"
      keyword={searchTerm}
      filters={filters}
      paginationOptions={paginationOptions}
      numberOfElements={numberOfElements}
      availableFilterKeys={[
        'workflow_id',
        'objectLabel',
        'objectMarking',
        'createdBy',
        'source_reliability',
        'creator_id',
        'created',
        'revoked',
        'killChainPhases',
        'name',
      ]}
    >
      {queryRef && (
      <React.Suspense fallback={ <> {Array(20)
        .fill(0)
        .map((_, idx) => (
          <NarrativeLine
            key={idx}
            dataColumns={dataColumns}
          />
        ))}
      </>
                  }
      >
        <NarrativesLines
          queryRef={queryRef}
          paginationOptions={paginationOptions}
          dataColumns={dataColumns}
          onLabelClick={helpers.handleAddFilter}
          setNumberOfElements={helpers.handleSetNumberOfElements}
        />
      </React.Suspense>
      )}
    </ListLines>
  );

  return (
    <>
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <NarrativeCreation paginationOptions={paginationOptions} />
      </Security>
    </>
  );
};

export default Narratives;
