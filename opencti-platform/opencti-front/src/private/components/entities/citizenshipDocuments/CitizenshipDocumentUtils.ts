import * as Yup from 'yup';
import { useDynamicSchemaCreationValidation, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';

export const getCitizenshipDocumentValidator = (mandatoryAttributes: string[]) => {
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().min(2),
    description: Yup.string().nullable(),
    x_opencti_citizenship_document_type: Yup.string().nullable(),
    createdBy: Yup.object().nullable(),
    objectLabel: Yup.array().nullable(),
    objectMarking: Yup.array().nullable(),
    x_opencti_workflow_id: Yup.object().nullable(),
  }, mandatoryAttributes);

  return useDynamicSchemaCreationValidation(mandatoryAttributes, basicShape);
};

export const CITIZENSHIP_DOCUMENT_ENTITY_TYPE = 'Citizenship-Document';
