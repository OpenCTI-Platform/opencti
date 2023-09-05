import React from 'react';
import {
  AttackPatternsLinesPaginationQuery,
  AttackPatternsLinesPaginationQuery$variables,
} from '@components/techniques/attack_patterns/__generated__/AttackPatternsLinesPaginationQuery.graphql';
import { AttackPatternLineDummy } from '@components/techniques/attack_patterns/AttackPatternLine';
import ListLines from '../../../components/list_lines/ListLines';
import AttackPatternsLines, { attackPatternsLinesQuery } from './attack_patterns/AttackPatternsLines';
import AttackPatternCreation from './attack_patterns/AttackPatternCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { Filters } from '../../../components/list_lines';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';

const LOCAL_STORAGE_KEY = 'view-attackPattern';

const AttackPatterns = () => {
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<AttackPatternsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      openExports: false,
      filters: {} as Filters,
    },
  );

  const renderLines = () => {
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
    const queryRef = useQueryLoading<AttackPatternsLinesPaginationQuery>(
      attackPatternsLinesQuery,
      paginationOptions,
    );
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        handleAddFilter={helpers.handleAddFilter}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleToggleExports={helpers.handleToggleExports}
        openExports={openExports}
        exportEntityType="Attack-Pattern"
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
          'creator',
          'created_start_date',
          'created_end_date',
          'revoked',
          'killChainPhase',
        ]}
      >
        {queryRef && (
            <React.Suspense
                fallback={
                  <>
                    {Array(20)
                      .fill(0)
                      .map((idx) => (
                            <AttackPatternLineDummy
                                key={idx}
                                dataColumns={dataColumns}
                            />
                      ))}
                  </>
                }
            >
            <AttackPatternsLines
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
  };

  return (
    <>
      {renderLines()}
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <AttackPatternCreation paginationOptions={paginationOptions} />
      </Security>
    </>
  );
};

export default AttackPatterns;
