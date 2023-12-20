import React from 'react';
import {
  AttackPatternsLinesPaginationQuery,
  AttackPatternsLinesPaginationQuery$variables,
} from '@components/techniques/attack_patterns/__generated__/AttackPatternsLinesPaginationQuery.graphql';
import { AttackPatternLineDummy } from '@components/techniques/attack_patterns/AttackPatternLine';
import ListLines from '../../../components/list_lines/ListLines';
import AttackPatternsLines, { attackPatternsLinesQuery } from './attack_patterns/AttackPatternsLines';
import AttackPatternCreation from './attack_patterns/AttackPatternCreation';
import { KnowledgeSecurity } from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';

const LOCAL_STORAGE_KEY = 'attackPattern';

const AttackPatterns = () => {
  const { t_i18n } = useFormatter();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<AttackPatternsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      openExports: false,
      filters: emptyFilterGroup,
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
        label: 'Original creation date',
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
        exportContext={{ entity_type: 'Attack-Pattern' }}
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
      >
        {queryRef && (
        <React.Suspense
          fallback={
            <>
              {Array(20)
                .fill(0)
                .map((_, idx) => (
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
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Techniques') }, { label: t_i18n('Attack patterns'), current: true }]} />
      {renderLines()}
      <KnowledgeSecurity needs={[KNOWLEDGE_KNUPDATE]} entity='Attack-Pattern'>
        <AttackPatternCreation paginationOptions={paginationOptions} />
      </KnowledgeSecurity>
    </>
  );
};

export default AttackPatterns;
