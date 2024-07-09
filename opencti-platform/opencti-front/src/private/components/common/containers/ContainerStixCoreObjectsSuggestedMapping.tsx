import React, { FunctionComponent, useEffect, useRef } from 'react';
import { graphql } from 'react-relay';
import {
  ContainerStixCoreObjectsSuggestedMappingLine,
  ContainerStixCoreObjectsSuggestedMappingLineDummy,
} from '@components/common/containers/ContainerStixCoreObjectsSuggestedMappingLine';
import { ContainerStixCoreObjectsSuggestedMappingQuery$data } from '@components/common/containers/__generated__/ContainerStixCoreObjectsSuggestedMappingQuery.graphql';
import { ContainerContent_container$data } from '@components/common/containers/__generated__/ContainerContent_container.graphql';
import ListLines from '../../../../components/list_lines/ListLines';
import useAuth from '../../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import Loader, { LoaderVariant } from '../../../../components/Loader';

// containers fetching is not good performance wise, we could find a better way to do it by moving it to backend if needed
export const containerStixCoreObjectsSuggestedMappingQuery = graphql`
  query ContainerStixCoreObjectsSuggestedMappingQuery(
    $id: ID!
    $contentSource: String!
    $contentType: AnalysisContentType!
  ) {
    stixCoreObjectAnalysis(id: $id, contentSource: $contentSource, contentType: $contentType) {
      ... on MappingAnalysis {
        analysisType
        analysisStatus
        analysisDate
        mappedEntities {
          matchedString
          isEntityInContainer
          ...ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity
          matchedEntity{
            id
            standard_id
          }
        }
      }
    }
    connectorsForAnalysis {
      id
    }
  }
`;

interface ContainerStixCoreObjectsSuggestedMappingProps {
  container: ContainerContent_container$data;
  suggestedMapping: ContainerStixCoreObjectsSuggestedMappingQuery$data
  suggestedMappingCount: Record<string, number>;
  height: number;
  handleAskNewSuggestedMapping: () => void;
  askingSuggestion: boolean;
  handleValidateSuggestedMapping: (mappingToAdd: { matchedString: string, matchedEntityId: string }[]) => void;
  removedEntities: string[];
  handleRemoveSuggestedMappingLine: (entityId: string) => void;
  changeToMappingMode: () => void;
}

export type MappedEntityType = NonNullable<NonNullable<ContainerStixCoreObjectsSuggestedMappingQuery$data['stixCoreObjectAnalysis']>['mappedEntities']>[number];

const ContainerStixCoreObjectsSuggestedMapping: FunctionComponent<
ContainerStixCoreObjectsSuggestedMappingProps
> = ({
  container,
  suggestedMapping,
  suggestedMappingCount,
  height,
  handleAskNewSuggestedMapping,
  askingSuggestion,
  removedEntities,
  handleRemoveSuggestedMappingLine,
}) => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;

  // The container ref is not defined on first render, causing infinite scroll issue in the ListLinesContent
  // we force re-render when the ref is ready
  const ref = useRef(null);
  const [, forceUpdate] = React.useReducer((o) => !o, true);
  useEffect(() => {
    forceUpdate();
  }, [ref?.current, askingSuggestion]);

  const LOCAL_STORAGE_KEY = `container-${container.id}-stixCoreObjectsSuggestedMapping`;
  const {
    viewStorage,
    helpers,
  } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    {
      id: container.id,
      types: ['Stix-Core-Object'],
      filters: emptyFilterGroup,
      searchTerm: '',
      sortBy: 'name',
      orderAsc: false,
      openExports: false,
      view: 'suggestedMapping',
    },
    true,
  );
  const {
    numberOfElements,
    filters,
    searchTerm,
    sortBy,
    orderAsc,
  } = viewStorage;
  const {
    handleSetNumberOfElements,
  } = helpers;

  const dataColumns = {
    entity_type: {
      label: 'Type',
      width: '20%',
      isSortable: true,
    },
    createdBy: {
      label: 'Author',
      width: '15%',
      isSortable: isRuntimeSort,
    },
    value: {
      label: 'Value',
      width: '27%',
      isSortable: false,
    },
    objectMarking: {
      label: 'Marking',
      width: '15%',
      isSortable: isRuntimeSort,
    },
    matched_text: {
      label: 'Matched text',
      width: '15%',
      isSortable: true,
    },
    mapping: {
      label: 'Mapping',
      width: '8%',
      isSortable: false,
    },
  };

  const mappedEntities = (suggestedMapping?.stixCoreObjectAnalysis?.mappedEntities ?? []);
  const filterMappedEntities = (mappedEntity: MappedEntityType) => {
    return !removedEntities.find((r) => r === mappedEntity.matchedEntity?.id);
  };
  const filteredMappedEntities = mappedEntities.filter((e) => filterMappedEntities(e));
  const mappedEntitiesWithNode = filteredMappedEntities.map((e) => { return { node: e }; });

  handleSetNumberOfElements({
    number: filteredMappedEntities.length,
    symbol: '',
    original: filteredMappedEntities.length,
  });

  return (
    <div>
      <div style={{ margin: 0, padding: '15px 0 0 0' }} ref={ref} >
        {askingSuggestion
          ? <Loader variant={LoaderVariant.inElement}/>
          : (
            <ListLines
              helpers={helpers}
              sortBy={sortBy}
              orderAsc={orderAsc}
              dataColumns={dataColumns}
              iconExtension={false}
              filters={filters}
              availableEntityTypes={['Stix-Core-Object']}
              keyword={searchTerm}
              secondaryAction={true}
              numberOfElements={numberOfElements}
              noPadding={true}
              mappingCount={filteredMappedEntities.length}
              disabledValidate={filteredMappedEntities.length <= 0}
              enableMappingView
              disableCards
            >
              <ListLinesContent
                initialLoading={false}
                loadMore={() => {}}
                hasMore={() => {}}
                isLoading={() => false}
                dataList={mappedEntitiesWithNode}
                globalCount={mappedEntitiesWithNode.length}
                LineComponent={ContainerStixCoreObjectsSuggestedMappingLine}
                DummyLineComponent={ContainerStixCoreObjectsSuggestedMappingLineDummy}
                dataColumns={dataColumns}
                contentMappingCount={suggestedMappingCount}
                handleRemoveSuggestedMappingLine={handleRemoveSuggestedMappingLine}
                height={height}
                containerRef={ref}
              />
            </ListLines>
          )
        }
      </div>
    </div>
  );
};

export default ContainerStixCoreObjectsSuggestedMapping;
