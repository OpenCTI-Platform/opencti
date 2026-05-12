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

import IconButton from '@common/button/IconButton';
import { AddOutlined, DeleteOutlined } from '@mui/icons-material';
import { Grid2 as Grid, Stack } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Field, FieldArray, useFormikContext } from 'formik';
import type { Theme } from '../../../../../../../components/Theme';
import AutocompleteField from '../../../../../../../components/AutocompleteField';
import Button from '../../../../../../../components/common/button/Button';
import { useFormatter } from '../../../../../../../components/i18n';
import { capitalizeFirstLetter } from '../../../../../../../utils/String';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../../../../utils/field';
import { isEmptyField } from '../../../../../../../utils/utils';
import PlaybookActionValueField from './PlaybookActionValueField';
import { attributesMultiple, PlaybookUpdateAction, PlaybookUpdateActionsForm } from './playbookAction-types';
import useActionFieldOptions from './useActionFieldOptions';

interface PlaybookFlowFieldActionsProps {
  operations?: string[];
}

const PlaybookFlowFieldActions = ({
  operations = ['add, replace, remove'],
}: PlaybookFlowFieldActionsProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const operationOptions: FieldOption[] = operations.map((op) => ({
    label: t_i18n(capitalizeFirstLetter(op)),
    value: op,
  }));

  const getActionFieldOptions = useActionFieldOptions();
  const { values, setFieldValue } = useFormikContext<PlaybookUpdateActionsForm>();
  const actions = values.actions ?? [];
  const formActionsValues = values.actionsFormValues ?? [];

  const actionsAreValid = actions.every((a) => {
    if (a.attribute === 'x_opencti_detection') return true;
    return a.op && a.attribute && a.value && a.value.length > 0;
  });

  return (
    <FieldArray
      name="actions"
      render={(arrayHelpers) => (
        <div style={fieldSpacingContainerStyle}>
          {actions.map((action, i) => {
            const fieldOptions = getActionFieldOptions(action);

            return (
              <div key={i}>
                <div style={{
                  position: 'relative',
                  width: '100%',
                  margin: '0 0 20px 0',
                  padding: '15px',
                  verticalAlign: 'middle',
                  border: `1px solid ${theme.palette.primary.main}`,
                  borderRadius: 4,
                  display: 'flex',
                }}
                >
                  <Grid container spacing={3} sx={{ width: '100%', alignItems: 'flex-end' }}>
                    <Grid size={{ xs: 3 }}>
                      <Field
                        component={AutocompleteField}
                        name={`actions.${i}.op`}
                        multiple={false}
                        textfieldprops={{
                          variant: 'standard',
                          label: t_i18n('Action type'),
                        }}
                        options={operationOptions}
                        isOptionEqualToValue={(option: FieldOption, val: string | FieldOption) => option.value === (typeof val === 'string' ? val : val.value)}
                        getOptionLabel={(option: string | FieldOption) => {
                          if (typeof option === 'string') {
                            return operationOptions.find((o) => o.value === option)?.label ?? option;
                          }
                          return option.label ?? '';
                        }}
                        onInternalChange={(_: string, val: FieldOption | null) => {
                          const newOp = val?.value ?? '';
                          setFieldValue(`actions.${i}`, { op: newOp });
                          if (formActionsValues[i] !== undefined) {
                            setFieldValue(`actionsFormValues.${i}`, null);
                          }
                        }}
                      />
                    </Grid>
                    <Grid size={{ xs: 3 }}>
                      <Field
                        component={AutocompleteField}
                        name={`actions.${i}.attribute`}
                        multiple={false}
                        disabled={isEmptyField(action.op)}
                        textfieldprops={{
                          variant: 'standard',
                          label: t_i18n('Field'),
                        }}
                        options={fieldOptions}
                        noOptionsText={t_i18n('None')}
                        isOptionEqualToValue={(option: FieldOption, val: string | FieldOption) => option.value === (typeof val === 'string' ? val : val.value)}
                        getOptionLabel={(option: string | FieldOption) => {
                          if (typeof option === 'string') {
                            return fieldOptions.find((o) => o.value === option)?.label ?? option;
                          }
                          return option.label ?? '';
                        }}
                        onInternalChange={(_: string, val: FieldOption | null) => {
                          const newAttribute = val?.value;
                          const newAction: PlaybookUpdateAction = { op: action.op };
                          if (newAttribute) newAction.attribute = newAttribute;
                          setFieldValue(`actions.${i}`, newAction);
                          if (formActionsValues[i] !== undefined) {
                            const isMultiple = attributesMultiple.includes(newAttribute ?? '');
                            setFieldValue(`actionsFormValues.${i}`, isMultiple ? [] : null);
                          }
                        }}
                      />
                    </Grid>
                    <Grid size={{ xs: 5 }}>
                      <PlaybookActionValueField
                        action={action}
                        index={i}
                      />
                    </Grid>

                    <Grid
                      size={{ xs: 1 }}
                      sx={{
                        display: 'flex',
                        justifyContent: 'center',
                        alignItems: 'center',
                      }}
                    >
                      <IconButton
                        aria-label="Delete"
                        disabled={actions.length === 1}
                        onClick={() => {
                          arrayHelpers.remove(i);
                          const newFormvalues = [...formActionsValues];
                          newFormvalues.splice(i, 1);
                          setFieldValue('actionsFormValues', newFormvalues);
                        }}
                      >
                        <DeleteOutlined />
                      </IconButton>
                    </Grid>

                  </Grid>
                </div>
              </div>
            );
          })}

          <Stack alignItems="center">
            <Button
              variant="tertiary"
              color="secondary"
              startIcon={<AddOutlined fontSize="small" />}
              disabled={!actionsAreValid}
              onClick={() => {
                arrayHelpers.push({});
              }}
            >
              {t_i18n('Add action')}
            </Button>
          </Stack>
        </div>
      )}
    />
  );
};

export default PlaybookFlowFieldActions;
