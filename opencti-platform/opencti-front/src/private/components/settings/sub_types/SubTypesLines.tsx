import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import usePreloadedFragment from '../../../../utils/hooks/usePreloadedFragment';
import { useFormatter } from '../../../../components/i18n';
import SubTypeLine from './SubTypesLine';
import { SubTypesLinesQuery } from './__generated__/SubTypesLinesQuery.graphql';
import { SubTypesLines_subTypes$key } from './__generated__/SubTypesLines_subTypes.graphql';
import { DataColumns } from '../../../../components/list_lines';
import { computeTLabel } from './statusFormUtils';

export const subTypesLinesQuery = graphql`
  query SubTypesLinesQuery {
    ...SubTypesLines_subTypes
  }
`;

const subTypesLinesFragment = graphql`
  fragment SubTypesLines_subTypes on Query {
    subTypes {
      edges {
        node {
          id
          label
          ...SubType_subType
        }
      }
    }
  }
`;

interface SubTypesLinesProps {
  queryRef: PreloadedQuery<SubTypesLinesQuery>
  keyword: string | undefined
  dataColumns: DataColumns
}

export type SubTypeEntity = { id: string, label: string, tlabel: string };

const SubTypesLines: FunctionComponent<SubTypesLinesProps> = ({
  queryRef,
  keyword,
  dataColumns,
}) => {
  const data = usePreloadedFragment<
  SubTypesLinesQuery,
  SubTypesLines_subTypes$key
  >({
    linesQuery: subTypesLinesQuery,
    linesFragment: subTypesLinesFragment,
    queryRef,
  });
  const { t } = useFormatter();

  const filterOnSubType = (subType: SubTypeEntity) => {
    if (keyword) {
      return subType.label.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
        || subType.tlabel.toLowerCase().indexOf(keyword.toLowerCase()) !== -1;
    }
    return true;
  };
  const sortOnSubType = (a: SubTypeEntity, b: SubTypeEntity) => {
    return (`${a.tlabel}`).localeCompare(`${b.tlabel}`);
  };

  const subTypes = (data?.subTypes?.edges ?? []).map((subType) => subType.node)
    .map((subType) => (computeTLabel(subType, t) as SubTypeEntity))
    .filter(filterOnSubType)
    .sort(sortOnSubType);

  return (
    <>
      {subTypes.map((subType) => <SubTypeLine
        key={subType.id} subTypeId={subType.id} subTypeLabel={subType.tlabel} dataColumns={dataColumns}/>)}
    </>
  );
};

export default SubTypesLines;
