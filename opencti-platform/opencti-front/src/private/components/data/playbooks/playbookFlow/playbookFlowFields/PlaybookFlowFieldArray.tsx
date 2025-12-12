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

import { MenuItem, Tooltip, TooltipProps } from '@mui/material';
import { Field } from 'formik';
import AutocompleteField from '../../../../../../components/AutocompleteField';
import { fieldSpacingContainerStyle } from '../../../../../../utils/field';
import useEntityTranslation from '../../../../../../utils/hooks/useEntityTranslation';

interface Option {
  const: string
  title: string
}

export interface PlaybookFlowFieldArrayProps {
  name: string
  label: string
  options: Option[]
  multiple?: boolean
}

const PlaybookFlowFieldArray = ({
  name,
  label,
  options,
  multiple = false,
}: PlaybookFlowFieldArrayProps) => {
  const { translateEntityType } = useEntityTranslation();
  const fieldOptions = [...options]
    .sort((a, b) =>
      translateEntityType(a?.title ?? '').localeCompare(
        translateEntityType(b?.title ?? '')
      )
    )
    .map(o => o.const);

  const findOption = (value: string) => {
    return options.find(o => o.const === value);
  };

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
      isOptionEqualToValue={(o: string, val: string) => o === val}
      renderOption={(props: TooltipProps, value: string) => {
        const option = findOption(value);
        if (!option) return null;
        return (
          <Tooltip
            {...props}
            key={option.const}
            title={translateEntityType(option.title)}
            placement="bottom-start"
          >
            <MenuItem value={option.const}>
              {/* value might be an entity type, we try to translate it */}
              {translateEntityType(option.title)}
            </MenuItem>
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
