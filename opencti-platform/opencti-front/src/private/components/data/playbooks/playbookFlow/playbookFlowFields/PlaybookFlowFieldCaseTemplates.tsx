import { useFormikContext } from 'formik';
import CaseTemplateField from '../../../../common/form/CaseTemplateField';
import { fieldSpacingContainerStyle } from '../../../../../../utils/field';

interface CaseTemplateForm {
  container_type: string
  caseTemplates: unknown[]
}

const CASES = ['Case-Incident', 'Case-Rfi', 'Case-Rft'];

const PlaybookFlowFieldCaseTemplates = () => {
  const { values, setFieldValue } = useFormikContext<CaseTemplateForm>();
  const { container_type } = values;

  const isCaseContainer = CASES.includes(container_type);
  // Clear case templates if new container type is not a case.
  if (values?.caseTemplates && values?.caseTemplates.length > 0 && !isCaseContainer) {
    setFieldValue('caseTemplates', []);
  }

  return (
    <CaseTemplateField
      label="Case templates"
      isDisabled={!isCaseContainer}
      containerStyle={fieldSpacingContainerStyle}
    />
  );
};

export default PlaybookFlowFieldCaseTemplates;
