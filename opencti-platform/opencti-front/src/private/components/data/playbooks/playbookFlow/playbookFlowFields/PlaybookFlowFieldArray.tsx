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
import { Field, useFormikContext } from 'formik';
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
  const { setFieldValue } = useFormikContext();

  const setOneOfValue = (value: Option) => {
    setFieldValue(name, value.const);
  };

  const setMultipleValue = (values: Option[]) => {
    setFieldValue(name, values.map((o) => (o.const)));
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
      options={options}
      onInternalChange={(_: string, option: Option | Option[]) => {
        if (Array.isArray(option)) {
          setMultipleValue(option);
        } else {
          setOneOfValue(option);
        }
      }}
      isOptionEqualToValue={(option: Option, value: string) => {
        return option.const === value;
      }}
      renderOption={(props: TooltipProps, value: Option) => (
        <Tooltip
          {...props}
          key={value.const}
          title={value.title}
          placement="bottom-start"
        >
          <MenuItem value={value.const}>
            {/* value might be an entity type, we try to translate it */}
            {translateEntityType(value.title)}
          </MenuItem>
        </Tooltip>
      )}
      getOptionLabel={(option: Option) => {
        return translateEntityType(option.title ?? option);
      }}
    />
  );
};

export default PlaybookFlowFieldArray;
