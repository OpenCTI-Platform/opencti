import React, { FunctionComponent } from 'react';
import {
  StixDomainObjectAttackPatternsKillChainContainer_data$data,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainContainer_data.graphql';
import AttackPatternsMatrixLines from '@components/techniques/attack_patterns/AttackPatternsMatrixLines';
import { NarrativesLinesPaginationQuery$variables } from '@components/techniques/narratives/__generated__/NarrativesLinesPaginationQuery.graphql';
import ToolBar from '@components/data/ToolBar';
import { AttackPatternNode } from '@components/techniques/attack_patterns/AttackPatternsMatrixLine';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import ListLines from '../../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';

const LOCAL_STORAGE_KEY = 'StixDomainObjectAttackPatternsKillChainMatrixInline';

interface StixDomainObjectAttackPatternsKillChainMatrixProps {
  data: StixDomainObjectAttackPatternsKillChainContainer_data$data;
}

const StixDomainObjectAttackPatternsKillChainMatrixInline: FunctionComponent<StixDomainObjectAttackPatternsKillChainMatrixProps> = (
  {
    data,
  },
) => {
  const { viewStorage, helpers } = usePaginationLocalStorage<NarrativesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      openExports: false,
      filters: {
        ...emptyFilterGroup,
      },
      view: 'lines',
    },
  );
  const {
    sortBy,
    searchTerm,
    orderAsc,
    filters,
  } = viewStorage;
  const attackPatterns = (data.attackPatterns?.edges ?? []).map((n) => n.node);

  const {
    onToggleEntity,
    numberOfSelectedElements,
    handleClearSelectedElements,
    selectedElements,
    deSelectedElements,
    selectAll,
    handleToggleSelectAll,
  } = useEntityToggle<AttackPatternNode>(LOCAL_STORAGE_KEY);

  const contextFilters = useBuildEntityTypeBasedFilterContext('Attack-Pattern', filters);

  const dataColumns = {
    killChainPhase: {
      label: 'Kill chain phase',
      width: '25%',
      isSortable: false,
    },
    x_mitre_id: {
      label: 'ID',
      width: '10%',
      isSortable: true,
    },
    name: {
      label: 'Name',
      width: '15%',
      isSortable: true,
    },
    objectLabel: {
      label: 'Labels',
      width: '15%',
      isSortable: false,
    },
    created: {
      label: 'Original creation date',
      width: '20%',
      isSortable: true,
    },
    objectMarking: {
      label: 'Marking',
      width: '15%',
      isSortable: true,
    },
  };

  return (
    <>
      <ListLines
        helpers={helpers}
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleToggleSelectAll={handleToggleSelectAll}
        selectAll={selectAll}
        iconExtension={true}
      >
        <AttackPatternsMatrixLines
          attackPatterns={attackPatterns}
          dataColumns={dataColumns}
          numberOfSelectedElements={numberOfSelectedElements}
          handleClearSelectedElements={handleClearSelectedElements}
          selectedElements={selectedElements}
          deSelectedElements={deSelectedElements}
          onToggleEntity={onToggleEntity}
          selectAll={selectAll}
          setNumberOfElements={helpers.handleSetNumberOfElements}
        />
      </ListLines>
      <ToolBar
        selectedElements={selectedElements}
        deSelectedElements={deSelectedElements}
        numberOfSelectedElements={numberOfSelectedElements}
        selectAll={selectAll}
        search={searchTerm}
        filters={contextFilters}
        handleClearSelectedElements={handleClearSelectedElements}
        type="Attack-Pattern"
      />
    </>
  );
};

export default StixDomainObjectAttackPatternsKillChainMatrixInline;
