import React, { Dispatch, FunctionComponent, SetStateAction, useState, } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import type { Option } from './ReferenceField';
import ReferenceField from './ReferenceField';
import { ArtifactFieldGetQuery, } from './__generated__/ArtifactFieldGetQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { Filter, FilterGroup } from '../../../../utils/filters/filtersUtils';

interface ArtifactFieldProps {
  attributeName: string;
  attributeValue?: Option;
  onChange: (name: string, value: Option) => void;
}

export const artifactQuery = graphql`
  query ArtifactFieldGetQuery($filters: FilterGroup) {
    stixCyberObservables(filters: $filters) {
      edges {
        node {
          id
          entity_type
          ... on Artifact {
            observable_value
          }
        }
      }
    }
  }
`;

interface ArtifactFieldComponentProps {
  queryRef: PreloadedQuery<ArtifactFieldGetQuery>;
  attributeName: string;
  attributeValue?: Option;
  onChange: (name: string, value: Option) => void;
  setSearch: Dispatch<SetStateAction<string | null>>;
}

const ArtifactFieldComponent: FunctionComponent<
ArtifactFieldComponentProps
> = ({ queryRef, attributeName, attributeValue, onChange, setSearch }) => {
  const data = usePreloadedQuery<ArtifactFieldGetQuery>(
    artifactQuery,
    queryRef,
  );
  const options = (data.stixCyberObservables?.edges ?? []).map(({ node }) => ({
    label: node.observable_value ?? node.id,
    value: node.id,
    type: node.entity_type,
  }));
  return (
    <ReferenceField
      name={attributeName}
      label={attributeName}
      onFocus={() => {}}
      onChange={onChange}
      options={options}
      onInputChange={setSearch}
      value={attributeValue}
    />
  );
};

const ArtifactField: FunctionComponent<ArtifactFieldProps> = ({
  attributeName,
  attributeValue,
  onChange,
}) => {
  const [search, setSearch] = useState<string | null>(null);
  const filtersContent = [
    { key: 'entity_type', values: ['Artifact'], operator: 'eq', mode: 'or' },
  ];
  if (search) {
    filtersContent.push({ key: 'name', values: [search], operator: 'eq', mode: 'or' });
  };
  const filters = {
    mode: 'and',
    filters: filtersContent,
    filterGroups: [],
  };
  const queryRef = useQueryLoading<ArtifactFieldGetQuery>(artifactQuery, {
    filters,
  });
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<span />}>
          <ArtifactFieldComponent
            queryRef={queryRef}
            attributeName={attributeName}
            attributeValue={attributeValue}
            onChange={onChange}
            setSearch={setSearch}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default ArtifactField;
