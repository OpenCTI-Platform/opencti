import { graphql, loadQuery, usePreloadedQuery } from 'react-relay';
import { environment } from '../../relay/environment';
import { useEntityTypesQuery } from './__generated__/useEntityTypesQuery.graphql';
import { useFormatter } from '../../components/i18n';
import { Option } from '../../private/components/common/form/ReferenceField';

const entityTypesQuery = graphql`
  query useEntityTypesQuery {
    stixDomainObjectTypes: subTypes(type: "Stix-Domain-Object") {
      edges {
        node {
          id
          label
        }
      }
    }
    stixCyberObservableTypes: subTypes(type: "Stix-Cyber-Observable") {
      edges {
        node {
          id
          label
        }
      }
    }
    stixCoreRelationshipTypes: subTypes(type: "stix-core-relationship") {
      edges {
        node {
          id
          label
        }
      }
    }
    stixRefRelationshipTypes: subTypes(type: "stix-ref-relationship") {
      edges {
        node {
          id
          label
        }
      }
    }
  }
`;

let EntityTypes: Record<string, Option[]> = {};
const queryRef = loadQuery<useEntityTypesQuery>(
  environment,
  entityTypesQuery,
  {},
);

const formatKey = (s: string) => s.replaceAll('-', '').replaceAll('_', '').toLowerCase();

const useEntityTypes = () => {
  const data = usePreloadedQuery<useEntityTypesQuery>(
    entityTypesQuery,
    queryRef,
  );

  const { t } = useFormatter();
  const optionBuilder = (type: string, d: { id: string; label: string }[]) => {
    return d
      .map(({ id, label }) => ({
        label: t(`${type}_${label}`),
        value: id,
      }))
      .sort((a, b) => a.label.localeCompare(b.label));
  };

  if (Object.keys(EntityTypes).length > 0) {
    EntityTypes = {
      [formatKey('stixCoreRelationshipTypes')]: optionBuilder(
        'relationship',
        data.stixCoreRelationshipTypes.edges.map(({ node }) => node),
      ),
      [formatKey('stixRefRelationshipTypes')]: optionBuilder(
        'relationship',
        data.stixRefRelationshipTypes.edges.map(({ node }) => node),
      ),
      [formatKey('stixDomainObjectTypes')]: optionBuilder(
        'entity',
        data.stixDomainObjectTypes.edges.map(({ node }) => node),
      ),
      [formatKey('stixCyberObservableTypes')]: optionBuilder(
        'entity',
        data.stixCyberObservableTypes.edges.map(({ node }) => node),
      ),
    };
  }

  return (types?: string[]) => (types
    ? types.flatMap((type) => EntityTypes[formatKey(type)])
    : Object.values(EntityTypes).flat());
};

export default useEntityTypes;
