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

    if (!schema || schema.type !== 'array') {
      reconciledData[key] = value;
      return;
    }

    if (typeof value === 'string' && value.trim()) {
      reconciledData[key] = value.split(',').map((item) => item.trim());
    } else if (Array.isArray(value)) {
      reconciledData[key] = value;
    } else {
      reconciledData[key] = [];
    }
  });

  return reconciledData;
};

export default reconcileManagedConnectorContractDataWithSchema;
