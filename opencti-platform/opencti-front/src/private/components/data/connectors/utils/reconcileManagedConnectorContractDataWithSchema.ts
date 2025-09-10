import { IngestionTypedProperty } from '@components/data/IngestionCatalog';

export type ManagerContractProperty = [string, IngestionTypedProperty];

type ReconciledValue = string | number | boolean | string[] | null | undefined;

type ReconciledData = Record<string, ReconciledValue>;

const reconcileManagedConnectorContractDataWithSchema = (
  contractValues: Record<string, string | boolean>,
  managerContractProps: ManagerContractProperty[],
): ReconciledData => {
  const reconciledData: ReconciledData = {};

  const schemaMap = new Map(managerContractProps);

  Object.entries(contractValues).forEach(([key, value]) => {
    const schema = schemaMap.get(key);

    if (!schema) {
      // If no schema found, keep original value
      reconciledData[key] = value;
      return;
    }

    switch (schema.type) {
      case 'array': {
        if (typeof value === 'string' && value.trim()) {
          reconciledData[key] = value.split(',').map((item) => item.trim());
        } else if (Array.isArray(value)) {
          reconciledData[key] = value;
        } else {
          reconciledData[key] = (schema.default as string[]) || [];
        }
        break;
      }

      case 'integer': {
        if (typeof value === 'string') {
          const parsed = parseInt(value, 10);
          reconciledData[key] = Number.isNaN(parsed) ? ((schema.default as number) || 0) : parsed;
        } else {
          reconciledData[key] = typeof value === 'number' ? value : ((schema.default as number) || 0);
        }
        break;
      }

      case 'boolean': {
        if (typeof value === 'string') {
          reconciledData[key] = value.toLowerCase() === 'true';
        } else {
          reconciledData[key] = Boolean(value);
        }
        break;
      }

      case 'string':
      default:
        reconciledData[key] = typeof value === 'string' ? value : ((schema.default as string) || '');
        break;
    }
  });

  managerContractProps.forEach(([key, schema]) => {
    if (reconciledData[key] === undefined && schema.default !== undefined) {
      reconciledData[key] = schema.default as ReconciledValue;
    }
  });

  return reconciledData;
};

export default reconcileManagedConnectorContractDataWithSchema;
