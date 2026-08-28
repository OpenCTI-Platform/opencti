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

import { Tooltip } from '@mui/material';
import { Field } from 'formik';
import ComboboxField from '../../../../../../components/ComboboxField';
import { fieldSpacingContainerStyle } from '../../../../../../utils/field';
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
  required?: boolean;
}

const PlaybookFlowFieldArray = ({
  name,
  label,
  options,
  multiple = false,
  required,
}: PlaybookFlowFieldArrayProps) => {
  const { translateEntityType } = useEntityTranslation();
  const fieldOptions = [...options]
    .sort((a, b) =>
      translateEntityType(a?.title ?? '').localeCompare(
        translateEntityType(b?.title ?? ''),
      ),
    )
    .map((o) => o.const);

  const findOption = (value: string) => {
    return options.find((o) => o.const === value);
  };

  return (
    <Field
      required={required}
      clearable={!required}
      multiple={multiple}
      component={ComboboxField}
      style={fieldSpacingContainerStyle}
      label={label}
      name={name}
      options={fieldOptions}
      // renderTags is gone: the library builds chips from getOptionLabel, which
      // is the same function the input and the filter use. The MUI version was
      // inconsistent — chips showed the RAW option.title while the input showed
      // the translated one — so chips are now translated like everything else.
      renderOption={(value: string) => {
        const option = findOption(value);
        if (!option) return null;
        return (
          <Tooltip
            title={translateEntityType(option.title)}
            placement="bottom-start"
          >
            {/* value might be an entity type, we try to translate it */}
            <span>{translateEntityType(option.title)}</span>
          </Tooltip>
        );
      }}
      getOptionLabel={(val: string) => {
        const option = findOption(val);
        return option ? translateEntityType(option.title) : '';
      }}
    />
  );
};

export default PlaybookFlowFieldArray;
