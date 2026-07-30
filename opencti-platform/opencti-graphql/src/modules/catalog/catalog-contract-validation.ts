import { UnsupportedError } from '../../config/errors';

const isEmptyField = (value: unknown): boolean => {
  return value === null
    || value === undefined
    || (typeof value === 'string' && value.trim().length === 0)
    || (Array.isArray(value) && value.length === 0);
};

type ValidatorCompiler = (cacheKey: string, jsonValidation: object) => void;

type ContractLike = {
  title?: string;
  slug?: string;
  manager_supported?: boolean;
  container_image?: string;
  container_type?: string;
  config_schema?: {
    type?: string;
    properties?: Record<string, unknown>;
    required?: string[];
    additionalProperties?: boolean;
  };
};

type ValidateManagerSupportedContractArgs = {
  catalogId: string;
  contract: ContractLike;
  compileValidator: ValidatorCompiler;
  onMissingConfigSchema?: (contractTitle: string) => void;
};

export const validateManagerSupportedContract = ({
  catalogId,
  contract,
  compileValidator,
  onMissingConfigSchema,
}: ValidateManagerSupportedContractArgs) => {
  if (!contract.manager_supported) {
    return;
  }

  const contractTitle = contract.title ?? 'unknown';
  if (!contract.config_schema) {
    onMissingConfigSchema?.(contractTitle);
    return;
  }

  if (isEmptyField(contract.container_image)) {
    throw UnsupportedError('Contract must define container_image field', { contractTitle });
  }
  if (isEmptyField(contract.container_type)) {
    throw UnsupportedError('Contract must define container_type field', { contractTitle });
  }

  const jsonValidation = {
    type: contract.config_schema.type,
    properties: contract.config_schema.properties,
    required: contract.config_schema.required,
    additionalProperties: contract.config_schema.additionalProperties,
  };
  try {
    compileValidator(`catalog-contract:${catalogId}:${contract.slug ?? 'unknown'}`, jsonValidation);
  } catch (err) {
    throw UnsupportedError('Contract must be a valid json schema definition', { cause: err });
  }
};
