import React, { FunctionComponent, useEffect, useRef } from 'react';
import { graphql } from 'react-relay';
import {
  ContainerStixCoreObjectsSuggestedMappingLine,
  ContainerStixCoreObjectsSuggestedMappingLineDummy,
} from '@components/common/containers/ContainerStixCoreObjectsSuggestedMappingLine';
import { ContainerStixCoreObjectsSuggestedMappingQuery$data } from '@components/common/containers/__generated__/ContainerStixCoreObjectsSuggestedMappingQuery.graphql';
import { ContainerMappingContent_container$data } from '@components/common/containers/__generated__/ContainerMappingContent_container.graphql';
import {
  ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity$data,
} from '@components/common/containers/__generated__/ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity.graphql';
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
  container: ContainerMappingContent_container$data;
  suggestedMappingCount: Record<string, number>;
  suggestedEntities: NonNullable<NonNullable<ContainerStixCoreObjectsSuggestedMappingQuery$data['stixCoreObjectAnalysis']>['mappedEntities']>
  height: number;
  askingSuggestion: boolean;
  handleRemoveSuggestedMappingLine: (entity: NonNullable<ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity$data['matchedEntity']>) => void;
}

const ContainerStixCoreObjectsSuggestedMapping: FunctionComponent<
ContainerStixCoreObjectsSuggestedMappingProps
> = ({
  container,
  suggestedMappingCount,
  suggestedEntities,
  height,
  askingSuggestion,
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

  const suggestedEntitiesWithNode = suggestedEntities.map((e) => { return { node: e }; });

  handleSetNumberOfElements({
    number: suggestedEntitiesWithNode.length,
    symbol: '',
    original: suggestedEntitiesWithNode.length,
  });

  return (
    <div ref={ref} >
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
            mappingCount={suggestedEntitiesWithNode.length}
            enableMappingView
            disableCards
          >
            <ListLinesContent
              initialLoading={false}
              loadMore={() => {}}
              hasMore={() => {}}
              isLoading={() => false}
              dataList={suggestedEntitiesWithNode}
              globalCount={suggestedEntitiesWithNode.length}
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
  );
};

export default ContainerStixCoreObjectsSuggestedMapping;
