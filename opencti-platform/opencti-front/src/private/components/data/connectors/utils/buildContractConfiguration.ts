import { FieldOption } from '../../../../../utils/field';

export type ManagedConnectorValues = {
  name: string;
  user_id?: string | FieldOption;
  automatic_user?: boolean;
  confidence_level?: string;
  creator?: FieldOption
};

const buildContractConfiguration = (values: ManagedConnectorValues) => {
  return Object.entries(values)
    .filter(([, value]) => value != null)
    .map(([key, value]) => {
      let computedValue = value;
      if (Array.isArray(value)) {
        computedValue = value.join(',');
      }

      return ({
        key,
        value: computedValue.toString(),
      });
    });
};

export default buildContractConfiguration;
