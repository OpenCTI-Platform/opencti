/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

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
