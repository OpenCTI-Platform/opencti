import { fetchQuery, graphql } from 'react-relay';
import { parseWorkErrorsQuery$data } from '@components/data/connectors/__generated__/parseWorkErrorsQuery.graphql';
import JSON5 from 'json5';
import { WorkMessages } from './ConnectorWorks';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { environment } from '../../../../relay/environment';

const parseWorkErrorsQuery = graphql`
  query parseWorkErrorsQuery($ids: [Any!]!) {
    stixObjectOrStixRelationships(
      filters: {
        mode: or
        filterGroups: []
        filters: [
          {
            key: "standard_id"
            values: $ids
            mode: or
          }
        ]
      }
    ) {
      edges {
        node {
          ... on StixCoreObject {
            id
            standard_id
            entity_type
            representative {
              main
            }
          }
          ... on StixRelationship {
            id
            standard_id
            entity_type
            representative {
              main
            }
            from {
              ... on StixCoreObject {
                id
                standard_id
                entity_type
                representative {
                  main
                }
              }
              ... on StixRelationship {
                id
                standard_id
                entity_type
                representative {
                  main
                }
              }
            }
            to {
              ... on StixCoreObject {
                id
                standard_id
                entity_type
                representative {
                  main
                }
              }
              ... on StixRelationship {
                id
                standard_id
                entity_type
                representative {
                  main
                }
              }
            }
          }
        }
      }
    }
  }
`;

type Entities = (NonNullable<NonNullable<NonNullable<NonNullable<parseWorkErrorsQuery$data>['stixObjectOrStixRelationships']>['edges']>[number]>['node'] | undefined)[];
export type ResolvedEntity = NonNullable<NonNullable<NonNullable<parseWorkErrorsQuery$data['stixObjectOrStixRelationships']>['edges']>[number]>['node'];
type ErrorLevel = 'Critical' | 'Warning' | 'Unclassified';

export interface FullParsedWorkMessage {
  isParsed: true,
  level: ErrorLevel,
  parsedError: {
    category: string,
    doc_code: string,
    message: string,
    entity: ResolvedEntity,
  }
  rawError: NonNullable<WorkMessages>[number],
}

export interface PartialParsedWorkMessage {
  isParsed: false,
  level: 'Unclassified',
  rawError: NonNullable<WorkMessages>[number],
}

export type ParsedWorkMessage = FullParsedWorkMessage | PartialParsedWorkMessage;

const criticalDocCodes = [
  // Doc_code
  'ELEMENT_ID_COLLISION',
  // Name
  'MULTIPLE_REFERENCES_ERROR',
  'UNSUPPORTED_ERROR',
  'DATABASE_ERROR',
  'INTERNAL_SERVER_ERROR',
];

const warningDocCodes = [
  // Doc_code
  'INCORRECT_INDICATOR_FORMAT',
  'INCORRECT_OBSERVABLE_FORMAT',
  'RESTRICTED_ELEMENT',
  'MULTIPLE_REFERENCES_FOUND',
  'SELF_REFERENCING_RELATION',
  'INSUFFICIENT_CONFIDENCE_LEVEL',
  'ELEMENT_NOT_FOUND',
  // Name
  'VALIDATION_ERROR',
  'MULTIPLE_ENTITIES_ERROR',
  'ACL_ERROR',
  'MISSING_REFERENCE_ERROR',
];

export const getLevel = (code: string): ErrorLevel => {
  if (criticalDocCodes.includes(code)) return 'Critical';
  if (warningDocCodes.includes(code)) return 'Warning';
  return 'Unclassified';
};

export const parseError = (error: NonNullable<NonNullable<WorkMessages>[number]>): ParsedWorkMessage => {
  // Try/Catch to prevent JSON.parse Exception
  try {
    const parsedSource = JSON5.parse(error.source ?? '{}');
    const source = parsedSource.type === 'bundle' ? parsedSource.objects[0] : parsedSource;
    const message = JSON5.parse((error.message ?? ''));
    const entityId = source.id;
    const fromId = source.source_ref;
    const toId = source.target_ref;

    const parsedError = {
      category: message.name,
      doc_code: message.doc_code ?? message.name,
      message: message.error_message,
      entity: {
        standard_id: entityId,
        representative: { main: getMainRepresentative(source, entityId) },
        from: fromId ? {
          standard_id: fromId,
        } : undefined,
        to: toId ? {
          standard_id: toId,
        } : undefined,
      },
    };

    return {
      isParsed: true,
      level: getLevel(message.doc_code ?? message.name ?? ''),
      parsedError,
      rawError: error,
    };
  } catch (_) {
    return {
      isParsed: false,
      level: 'Unclassified',
      rawError: error,
    };
  }
};

export const resolveError = (error: ParsedWorkMessage, entities: Entities): ParsedWorkMessage => {
  if (error.isParsed) {
    const errorParsed = error;
    entities.forEach((entity) => {
      if (!entity) return;
      if (entity.standard_id === error.parsedError.entity.standard_id) {
        errorParsed.parsedError.entity = entity;
      } else if (entity.standard_id === error.parsedError.entity.from?.standard_id) {
        errorParsed.parsedError.entity = { ...error.parsedError.entity, from: entity };
      } else if (entity.standard_id === error.parsedError.entity.to?.standard_id) {
        errorParsed.parsedError.entity = { ...error.parsedError.entity, to: entity };
      }
    });
    return errorParsed;
  }
  return error;
};

// Create custom error object from stringified error
const parseWorkErrors = async (errorsList: WorkMessages): Promise<ParsedWorkMessage[]> => {
  const ids: string[] = [];

  const parsedList: ParsedWorkMessage[] = (errorsList ?? []).flatMap((error) => {
    if (!error) return [];
    const errorParsed = parseError(error);
    if (errorParsed.isParsed) {
      ids.push(errorParsed.parsedError.entity.standard_id ?? '');
      if (errorParsed.parsedError.entity.from) ids.push(errorParsed.parsedError.entity.from.standard_id ?? '');
      if (errorParsed.parsedError.entity.to) ids.push(errorParsed.parsedError.entity.to.standard_id ?? '');
    }
    return errorParsed;
  });

  if (ids.length < 1) return parsedList;
  // try to resolve entities
  const entities: Entities = await fetchQuery(
    environment,
    parseWorkErrorsQuery,
    { ids },
  )
    .toPromise()
    .then((data) => {
      return ((data as parseWorkErrorsQuery$data)?.stixObjectOrStixRelationships?.edges ?? []).map((n) => n?.node);
    });
  return parsedList.map((error) => {
    return resolveError(error, entities);
  });
};

export default parseWorkErrors;
