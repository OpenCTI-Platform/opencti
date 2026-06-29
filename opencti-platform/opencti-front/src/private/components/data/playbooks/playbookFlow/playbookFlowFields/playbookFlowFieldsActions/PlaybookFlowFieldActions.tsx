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
import { graphql, useLazyLoadQuery } from 'react-relay';
import type { Theme } from '../../../../../../../components/Theme';
import AutocompleteField from '../../../../../../../components/AutocompleteField';
import Button from '../../../../../../../components/common/button/Button';
import { useFormatter } from '../../../../../../../components/i18n';
import { capitalizeFirstLetter } from '../../../../../../../utils/String';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../../../../utils/field';
import { isEmptyField } from '../../../../../../../utils/utils';
import PlaybookActionValueField from './PlaybookActionValueField';
import { attributesMultiple, PlaybookUpdateAction, PlaybookUpdateActionsForm } from './playbookAction-types';
import useActionFieldOptions, { CustomFieldOption } from './useActionFieldOptions';
import type { PlaybookFlowFieldActionsCustomFieldDefinitionsQuery } from './__generated__/PlaybookFlowFieldActionsCustomFieldDefinitionsQuery.graphql';

const customFieldDefinitionsQuery = graphql`
  query PlaybookFlowFieldActionsCustomFieldDefinitionsQuery {
    customFieldDefinitions(first: 200) {
      edges {
        node {
          id
          name
          label
          field_type
          select_options
        }
      }
    }
  }
`;

interface PlaybookFlowFieldActionsProps {
  operations?: string[];
}

const PlaybookFlowFieldActions = ({
  operations = ['add', 'replace', 'remove'],
}: PlaybookFlowFieldActionsProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const operationOptions: FieldOption[] = operations.map((op) => ({
    label: t_i18n(capitalizeFirstLetter(op)),
    value: op,
  }));

  // Load all custom field definitions to inject them into the Field dropdown
  const customFieldData = useLazyLoadQuery<PlaybookFlowFieldActionsCustomFieldDefinitionsQuery>(
    customFieldDefinitionsQuery,
    {},
    { fetchPolicy: 'store-or-network' },
  );
  const customFieldOptions: CustomFieldOption[] = (
    customFieldData?.customFieldDefinitions?.edges ?? []
  ).map(({ node }) => ({
    label: node.label,
    value: `x_opencti_cf_${node.name}`,
    field_type: node.field_type as CustomFieldOption['field_type'],
    select_options: (node.select_options ?? []) as string[],
  }));

  const getActionFieldOptions = useActionFieldOptions(customFieldOptions);
  const { values, setFieldValue } = useFormikContext<PlaybookUpdateActionsForm>();
  const actions = values.actions ?? [];
  const formActionsValues = values.actionsFormValues ?? [];

  const actionsAreValid = actions.every((a) => {
    if (a.attribute === 'x_opencti_detection') return true;
    return a.op && a.attribute && a.value && a.value.length > 0;
  });

  /**
   * Returns the label for a given option.
   * Handles both string values and FieldOption objects.
   */
  const getOptionLabel = (options: FieldOption[]) => (option: string | FieldOption): string => {
    if (typeof option === 'string') {
      return options.find((o) => o.value === option)?.label ?? option;
    }
    return option.label ?? '';
  };

  /**
   * Reset the action when the operation changes.
   * Clears attribute, value, and form display value.
   */
  const handleOperationChange = (index: number, val: FieldOption | null) => {
    const newOp = val?.value ?? '';
    setFieldValue(`actions.${index}`, { op: newOp });
    if (formActionsValues[index] !== undefined) {
      setFieldValue(`actionsFormValues.${index}`, null);
    }
  };

  /**
   * Reset the action value when the attribute changes.
   * Keeps the current operation and sets the new attribute.
   */
  const handleAttributeChange = (index: number, currentOp: string | undefined, val: FieldOption | null) => {
    const newAttribute = val?.value;
    const newAction: PlaybookUpdateAction = { op: currentOp };
    if (newAttribute) newAction.attribute = newAttribute;
    setFieldValue(`actions.${index}`, newAction);
    if (formActionsValues[index] !== undefined) {
      const isMultiple = attributesMultiple.includes(newAttribute ?? '');
      setFieldValue(`actionsFormValues.${index}`, isMultiple ? [] : null);
    }
  };

  /**
   * Remove an action and its associated form display value.
   */
  const handleDeleteAction = (index: number, remove: (index: number) => void) => {
    remove(index);
    const newFormValues = [...formActionsValues];
    newFormValues.splice(index, 1);
    setFieldValue('actionsFormValues', newFormValues);
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
                        getOptionLabel={getOptionLabel(operationOptions)}
                        onInternalChange={(_: string, val: FieldOption | null) => handleOperationChange(i, val)}
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
                        getOptionLabel={getOptionLabel(fieldOptions)}
                        onInternalChange={(_: string, val: FieldOption | null) => handleAttributeChange(i, action.op, val)}
                      />
                    </Grid>
                    <Grid size={{ xs: 5 }}>
                      <PlaybookActionValueField
                        action={action}
                        index={i}
                        customFieldOptions={customFieldOptions}
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
                        onClick={() => handleDeleteAction(i, arrayHelpers.remove)}
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
                const newFormvalues = [...formActionsValues, []];
                setFieldValue('actionsFormValues', newFormvalues);
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
