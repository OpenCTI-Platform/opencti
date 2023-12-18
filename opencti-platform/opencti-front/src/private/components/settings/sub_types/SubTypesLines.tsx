import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import usePreloadedFragment from '../../../../utils/hooks/usePreloadedFragment';
import { useFormatter } from '../../../../components/i18n';
import SubTypeLine from './SubTypesLine';
import { SubTypesLinesQuery } from './__generated__/SubTypesLinesQuery.graphql';
import { SubTypesLines_subTypes$key } from './__generated__/SubTypesLines_subTypes.graphql';
import { DataColumns } from '../../../../components/list_lines';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';

export const subTypesLinesQuery = graphql`
  query SubTypesLinesQuery {
    ...SubTypesLines_subTypes
  }
`;

export const subTypesLinesFragment = graphql`
  fragment SubTypesLines_subTypes on Query {
    subTypes {
      edges {
        node {
          label
          overridable
          ...SubTypesLine_node
        }
      }
    }
  }
`;

interface SubTypesLinesProps {
  queryRef: PreloadedQuery<SubTypesLinesQuery>;
  keyword: string | undefined;
  dataColumns: DataColumns;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  selectedElements: Record<string, { id: string }>;
  deSelectedElements: Record<string, { id: string }>;
  selectAll: boolean;
  onToggleEntity: (entity: { id: string }) => void;
}

const SubTypesLines: FunctionComponent<SubTypesLinesProps> = ({
  queryRef,
  keyword,
  dataColumns,
  setNumberOfElements,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleEntity,
}) => {
  const data = usePreloadedFragment<
  SubTypesLinesQuery,
  SubTypesLines_subTypes$key
  >({
    queryDef: subTypesLinesQuery,
    fragmentDef: subTypesLinesFragment,
    queryRef,
  });
  const { t_i18n } = useFormatter();
  const filterOnSubType = ({ node }: { node: { label: string } }) => {
    if (keyword) {
      return (
        node.label.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
        || t_i18n(`entity_${node.label}`)
          .toLowerCase()
          .indexOf(keyword.toLowerCase()) !== -1
      );
    }
    return true;
  };
  const sortOnSubType = (
    edgeA: { node: { label: string } },
    edgeB: { node: { label: string } },
  ) => {
    return t_i18n(`entity_${edgeA.node.label}`).localeCompare(
      t_i18n(`entity_${edgeB.node.label}`),
    );
  };
  const subTypes = (data?.subTypes?.edges ?? [])
    .filter(filterOnSubType)
    .sort(sortOnSubType);
  setNumberOfElements({
    number: subTypes.length.toString(),
    symbol: '',
    original: subTypes.length,
  });
  return (
    <ListLinesContent
      initialLoading={false}
      loadMore={() => {}}
      hasMore={() => {}}
      isLoading={() => false}
      dataList={subTypes}
      globalCount={subTypes.length}
      LineComponent={SubTypeLine}
      dataColumns={dataColumns}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      onToggleEntity={onToggleEntity}
      selectAll={selectAll}
    />
  );
};

export default SubTypesLines;
