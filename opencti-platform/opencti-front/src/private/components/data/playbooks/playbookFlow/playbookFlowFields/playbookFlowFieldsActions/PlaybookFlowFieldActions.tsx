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
import { Grid2 as Grid, MenuItem, Stack } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Field, FieldArray, useFormikContext } from 'formik';
import type { Theme } from '../../../../../../../components/Theme';
import Button from '../../../../../../../components/common/button/Button';
import SelectField from '../../../../../../../components/fields/SelectField';
import { useFormatter } from '../../../../../../../components/i18n';
import { capitalizeFirstLetter } from '../../../../../../../utils/String';
import { fieldSpacingContainerStyle } from '../../../../../../../utils/field';
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
  const getActionFieldOptions = useActionFieldOptions();
  const { values, setFieldValue } = useFormikContext<PlaybookUpdateActionsForm>();
  const actions = values.actions ?? [];
  const formActionsValues = values.actionsFormValues ?? [];

  const actionsAreValid = actions.every((a) => {
    if (a.attribute === 'x_opencti_detection') return true;
    return a.op && a.attribute && a.value && a.value.length > 0;
  });

  /**
   * When changing either the operation (op) or the attribute, we need to reset
   * the field for the value of the action.
   *
   * @param index Index of the action in the array of actions in the form.
   * @param attribute The new value of attribute concerned by the action (undefined = it's the 'op' that has changed).
   */
  const resetActionValue = (index: number, attribute?: string) => {
    if (actions[index]) {
      const newValue: PlaybookUpdateAction = {
        // By default we only set in the new object the operation.
        op: actions[index].op,
      };
      if (attribute) {
        newValue.attribute = attribute;
      }
      setFieldValue(`actions.${index}`, newValue);
    }
    if (formActionsValues[index] !== undefined) {
      // We also reset in the array containing form data, it's either null or empty array
      // depending of the kind of attribute manipulated (multiple or not).
      const isMultiple = attributesMultiple.includes(attribute ?? '');
      setFieldValue(`actionsFormValues.${index}`, isMultiple ? [] : null);
    }
  };

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
                  <Grid container spacing={3} sx={{ width: '100%' }}>
                    <Grid size={{ xs: 3 }}>
                      <Field
                        component={SelectField}
                        variant="standard"
                        name={`actions.${i}.op`}
                        containerstyle={{ width: '100%' }}
                        label={t_i18n('Action type')}
                        onChange={() => resetActionValue(i)}
                      >
                        {operations.map((op) => (
                          <MenuItem key={op} value={op}>
                            {t_i18n(capitalizeFirstLetter(op))}
                          </MenuItem>
                        ))}
                      </Field>
                    </Grid>
                    <Grid size={{ xs: 3 }}>
                      <Field
                        component={SelectField}
                        disabled={isEmptyField(action.op)}
                        variant="standard"
                        name={`actions.${i}.attribute`}
                        containerstyle={{ width: '100%' }}
                        label={t_i18n('Field')}
                        onChange={(_: string, val: string) => resetActionValue(i, val)}
                      >
                        {fieldOptions.length === 0
                          ? <MenuItem value="none">{t_i18n('None')}</MenuItem>
                          : fieldOptions.map((option) => (
                              <MenuItem key={option.value} value={option.value}>
                                {option.label}
                              </MenuItem>
                            ))
                        }
                      </Field>
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
