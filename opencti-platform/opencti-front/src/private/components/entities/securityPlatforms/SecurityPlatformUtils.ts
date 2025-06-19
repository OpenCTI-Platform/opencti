import * as Yup from 'yup';
import { useDynamicSchemaCreationValidation, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';

export const SECURITY_PLATFORM_TYPE = 'SecurityPlatform';

export const getSecurityPlatformValidator = (mandatoryAttributes: string[]) => {
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().min(2),
    description: Yup.string().nullable(),
    security_platform_type: Yup.string().nullable(),
    createdBy: Yup.object().nullable(),
    objectLabel: Yup.array().nullable(),
    objectMarking: Yup.array().nullable(),
    x_opencti_workflow_id: Yup.object().nullable(),
  }, mandatoryAttributes);

  return useDynamicSchemaCreationValidation(mandatoryAttributes, basicShape);
};
