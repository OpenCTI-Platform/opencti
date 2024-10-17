import { WorkMessages } from './ConnectorWorks';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';

export interface FullParsedWorkMessage {
  isParsed: true,
  level: 'Critical' | 'Warning' | 'Unclassified',
  parsedError: {
    category: string,
    message: string,
    entity: {
      id: string,
      name: string,
      type: string,
    }
  }
  rawError: NonNullable<WorkMessages>[number],
}

export interface PartialParsedWorkMessage {
  isParsed: false,
  level: 'Unclassified',
  rawError: NonNullable<WorkMessages>[number],
}

export type ParsedWorkMessage = FullParsedWorkMessage | PartialParsedWorkMessage;

const criticalErrorTypes = [
  'MULTIPLE_REFERENCES_ERROR',
  'UNSUPPORTED_ERROR',
  'DATABASE_ERROR',
  'INTERNAL_SERVER_ERROR',
];

const warningErrorTypes = [
  'VALIDATION_ERROR',
  'MULTIPLE_ENTITIES_ERROR',
  'ACL_ERROR',
  'MISSING_REFERENCE_ERROR',
];

// Create custom error object from error because errors are in JSON
const parseWorkErrors = (errorsList: WorkMessages): ParsedWorkMessage[] => {
  // sort error by critical level
  const getLevel = (type: string) => {
    if (criticalErrorTypes.includes(type)) return 'Critical';
    if (warningErrorTypes.includes(type)) return 'Warning';
    return 'Unclassified';
  };
  return (errorsList ?? []).flatMap((error) => {
    if (!error) return [];
    // Try/Catch to prevent JSON.parse Exception
    try {
      const source = JSON.parse(error.source ?? '');
      const message = JSON.parse((error.message ?? '').replace(/'/g, '"'));
      const entityId = source.name || source.id;
      return {
        isParsed: true,
        level: getLevel(message.name ?? ''),
        parsedError: {
          category: message.name,
          message: message.error_message,
          entity: {
            id: entityId,
            name: getMainRepresentative(source, entityId),
            type: source.type,
          },
        },
        rawError: error,
      };
    } catch (_) {
      return {
        isParsed: false,
        level: 'Unclassified',
        rawError: error,
      };
    }
  });
};

export default parseWorkErrors;
