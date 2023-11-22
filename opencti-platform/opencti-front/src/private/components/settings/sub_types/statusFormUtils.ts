import * as Yup from 'yup';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useSchemaAttributes';

const OBJECT_TYPE = 'Status';

export const statusValidation = (t: (name: string | object) => string) => useSchemaCreationValidation(OBJECT_TYPE, {
  template: Yup.object(),
  order: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number')),
});

export interface StatusForm {
  template: {
    label: string;
    value: string;
    color: string;
  } | null;
  order: string;
}
