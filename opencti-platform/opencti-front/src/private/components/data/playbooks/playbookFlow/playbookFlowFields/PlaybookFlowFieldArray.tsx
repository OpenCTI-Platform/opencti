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

import { Field } from 'formik';
import AutocompleteField from '../../../../../../components/AutocompleteField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../../../utils/field';
import useEntityTranslation from '../../../../../../utils/hooks/useEntityTranslation';

interface Option {
  const: string;
  title: string;
}

export interface PlaybookFlowFieldArrayProps {
  name: string;
  label: string;
  options: Option[];
  multiple?: boolean;
}

const PlaybookFlowFieldArray = ({
  name,
  label,
  options,
  multiple = false,
}: PlaybookFlowFieldArrayProps) => {
  const { translateEntityType } = useEntityTranslation();
  const fieldOptions: FieldOption[] = [...options]
    .sort((a, b) =>
      translateEntityType(a?.title ?? '').localeCompare(
        translateEntityType(b?.title ?? ''),
      ),
    )
    .map((o) => ({
      value: o.const,
      label: translateEntityType(o.title),
    }));

  return (
    <Field
      fullWidth
      multiple={multiple}
      component={AutocompleteField}
      style={fieldSpacingContainerStyle}
      textfieldprops={{
        variant: 'standard',
        label,
      }}
      name={name}
      options={fieldOptions}
    />
  );
};

export default PlaybookFlowFieldArray;
