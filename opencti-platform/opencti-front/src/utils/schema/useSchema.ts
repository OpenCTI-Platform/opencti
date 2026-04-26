import { useContext, useMemo } from 'react';
import { useFragment } from 'react-relay';
import { graphql } from 'relay-runtime';
import { FieldOption } from '../field';
import type { useSchema_data$key } from './__generated__/useSchema_data.graphql';
import { SchemaPreloadedDataContext } from './SchemaPreloadedContext';

const schemaFragment = graphql`
  fragment useSchema_data on Query {
    schemaSCOs: subTypes(type: "Stix-Cyber-Observable") {
      edges {
        node {
          id
          label
        }
      }
    }
    schemaSDOs: subTypes(type: "Stix-Domain-Object") {
      edges {
        node {
          id
          label
        }
      }
    }
    schemaSMOs: subTypes(type: "Stix-Meta-Object") {
      edges {
        node {
          id
          label
        }
      }
    }
    schemaSCRs: subTypes(type: "stix-core-relationship") {
      edges {
        node {
          id
          label
        }
      }
    }
    schemaRelationsTypesMapping {
      key
      values
    }
    schemaRelationsRefTypesMapping {
      key
      values {
        name
        toTypes
      }
    }
    filterKeysSchema {
      entity_type
      filters_schema {
        filterKey
        filterDefinition {
          filterKey
          label
          type
          multiple
          subEntityTypes
          elementsForFilterValuesSearch
          subFilters {
            filterKey
            label
            type
            multiple
            subEntityTypes
            elementsForFilterValuesSearch
          }
        }
      }
    }
  }
`;

export interface AvailableEntityOption extends FieldOption {
  type: string;
  id: string;
}

export type FilterDefinition = {
  filterKey: string;
  label: string;
  type: string; // boolean, date, integer, float, id, string, text, or object
  multiple: boolean;
  subEntityTypes: string[];
  elementsForFilterValuesSearch: string[]; // not empty if type = 'id', type = 'enum' or type = 'vocabulary'
  subFilters?: FilterDefinition[] | null;
};

export type SchemaType = {
  scos: { id: string; label: string }[];
  sdos: { id: string; label: string }[];
  smos: { id: string; label: string }[];
  scrs: { id: string; label: string }[];
  schemaRelationsTypesMapping: Map<string, readonly string[]>;
  schemaRelationsRefTypesMapping: Map<string, readonly { readonly name: string; readonly toTypes: readonly string[] }[]>;
  filterKeysSchema: Map<string, Map<string, FilterDefinition>>;
};

export const useSchema = () => {
  const { preloadedData } = useContext(SchemaPreloadedDataContext);
  const data = useFragment<
    useSchema_data$key
  >(schemaFragment, preloadedData);
  if (!data) {
    throw new Error('No data for platformModuleHelper');
  }
  const {
    schemaSCOs,
    schemaSDOs,
    schemaSMOs,
    schemaSCRs,
    schemaRelationsTypesMapping,
    schemaRelationsRefTypesMapping,
    filterKeysSchema,
  } = data;
  const schema = useMemo(() => ({
    scos: schemaSCOs.edges.map((sco) => sco.node),
    sdos: schemaSDOs.edges.map((sco) => sco.node),
    smos: schemaSMOs.edges.map((smo) => smo.node),
    scrs: schemaSCRs.edges.map((scr) => scr.node),
    schemaRelationsTypesMapping: new Map(schemaRelationsTypesMapping.map((n) => [n.key, n.values])),
    schemaRelationsRefTypesMapping: new Map(schemaRelationsRefTypesMapping.map((n) => [n.key, n.values])),
    filterKeysSchema: new Map(filterKeysSchema.map((n) => {
      const filtersSchema = new Map(n.filters_schema.map((o) => [o.filterKey, o.filterDefinition as FilterDefinition]));
      return [n.entity_type, filtersSchema];
    })),
  }), [
    schemaSCOs,
    schemaSDOs,
    schemaSMOs,
    schemaSCRs,
    schemaRelationsTypesMapping,
    schemaRelationsRefTypesMapping,
    filterKeysSchema,
  ]);

  const relationshipsNames = schema.scrs.map(({ label }) => label);

  const isRelationship = (entityType: string) => {
    return relationshipsNames.includes(entityType.toLowerCase());
  };

  const availableEntityTypes = useMemo(() => {
    const { sdos, scos, smos } = schema;
    return [
      ...sdos.map((sdo) => ({
        ...sdo,
        value: sdo.id,
        type: 'entity_Stix-Domain-Objects',
      })),
      ...scos.map((sco) => ({
        ...sco,
        value: sco.id,
        type: 'entity_Stix-Cyber-Observables',
      })),
      ...smos.map((smo) => ({
        ...smo,
        value: smo.id,
        type: 'entity_Stix-Meta-Objects',
      })),
    ];
  }, [schema]);

  const availableAndAbstractEntityTypes = availableEntityTypes.map((e) => e.id)
    .concat(['Stix-Domain-Object', 'Stix-Core-Object', 'Stix-Cyber-Observable']);

  return {
    allEntityTypes: availableAndAbstractEntityTypes,
    availableEntityTypes,
    isRelationship,
    schema,
  };
};
