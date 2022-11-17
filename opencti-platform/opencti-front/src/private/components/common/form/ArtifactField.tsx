import React, { FunctionComponent, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import type { Option } from './ReferenceField';
import ReferenceField from './ReferenceField';
import { ArtifactFieldGetQuery, StixCyberObservablesFiltering } from './__generated__/ArtifactFieldGetQuery.graphql';

interface ArtifactFieldProps {
  attributeName: string,
  attributeValue?: Option,
  onChange: (name: string, value: Option) => void,
}

export const artifactQuery = graphql`
  query ArtifactFieldGetQuery ($filters: [StixCyberObservablesFiltering]){
    stixCyberObservables(filters: $filters){
      edges{
        node{
          id
          ... on Artifact {
            observable_value
          }
        }
      }
    }
  }
`;

const ArtifactField: FunctionComponent<ArtifactFieldProps> = ({ attributeName, attributeValue, onChange }) => {
  const [search, setSearch] = useState<string | null>(null);
  const filters = [
    { key: ['entity_type'], values: ['artifact'] },
    search ? { key: ['name'], values: [search] } : undefined]
    .filter((f) => Boolean(f)) as StixCyberObservablesFiltering[];
  const data = useLazyLoadQuery<ArtifactFieldGetQuery>(artifactQuery, { filters });

  const options = (data.stixCyberObservables?.edges ?? []).map(({ node }) => ({
    label: node.observable_value ?? node.id,
    value: node.id,
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

export default ArtifactField;
