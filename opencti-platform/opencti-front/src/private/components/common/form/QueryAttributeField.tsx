import React, { FunctionComponent, ReactElement } from 'react';
import { Field, FieldArray } from 'formik';
import Button from '@mui/material/Button';
import { IconButton } from '@mui/material';
import { AddOutlined, DeleteOutlined } from '@mui/icons-material';
import { graphql } from 'react-relay';
import Paper from '@mui/material/Paper';
import {
  ThreatActorIndividualEditionBiographics_ThreatActorIndividual$data,
} from '@components/threats/threat_actors_individual/__generated__/ThreatActorIndividualEditionBiographics_ThreatActorIndividual.graphql';
import MenuItem from '@mui/material/MenuItem';
import { GenericContext } from '../model/GenericContextModel';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import useUserMetric from '../../../../utils/hooks/useUserMetric';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { isNotEmptyField } from '../../../../utils/utils';
import SelectField from '../../../../components/fields/SelectField';

export const individualHeaderMutation = graphql`
  mutation QueryAttributeFieldIndividualMutation($id: ID!, $input: [EditInput]!) {
    threatActorIndividualFieldPatch(id: $id, input: $input) {
      height {
        index
        measure
        date_seen
      }
    }
  }
`;

interface QueryAttributeFieldEditProps {
  id: string;
  name: string;
  values: ThreatActorIndividualEditionBiographics_ThreatActorIndividual$data['height'];
  containerStyle: { marginTop: number; width: string };
  setFieldValue?: (name: string, value: unknown) => void;
  editContext?: readonly (GenericContext | null)[] | null;
}
export const QueryAttributeFieldEdit: FunctionComponent<QueryAttributeFieldEditProps> = ({
  name,
  id,
  values,
  containerStyle,
  editContext = [],
}): ReactElement => {
  const { t_i18n } = useFormatter();
  const { lengthPrimaryUnit, heightToPivotFormat } = useUserMetric();
  return (
    <div style={containerStyle}>
      <FieldArray
        name={name}
        render={(arrayHelpers) => (
          <div id="total_attributes">
            {(values ?? []).map((height, index) => {
              return (
                <div
                  key={index}
                  style={{ marginTop: 20, width: '100%', position: 'relative' }}
                >
                  <div
                    style={{
                      paddingRight: 50,
                      display: 'grid',
                      gap: 20,
                      gridTemplateColumns: 'repeat(2, 1fr)',
                    }}
                  >
                    <Field
                      component={TextField}
                      variant="standard"
                      type="number"
                      slotProps={{ input: { min: 0 } }}
                      name={`${name}.${index}.measure`}
                      label={t_i18n(`Header (${lengthPrimaryUnit})`)}
                      onSubmit={(_: string, measure: string) => {
                        if (isNotEmptyField(measure)) {
                          commitMutation({
                            ...defaultCommitMutation,
                            mutation: individualHeaderMutation,
                            variables: {
                              id,
                              input: {
                                key: 'height',
                                value: [heightToPivotFormat(measure)],
                                object_path: `/height/${height.index}/measure`,
                                operation: 'replace',
                              },
                            },
                          });
                        }
                      }}
                    />
                    <Field
                      component={DateTimePickerField}
                      id={`height_date_${index}`}
                      name={`${name}.${index}.date_seen`}
                      onSubmit={(_: string, date_seen: string) => {
                        if (isNotEmptyField(date_seen)) {
                          commitMutation({
                            ...defaultCommitMutation,
                            mutation: individualHeaderMutation,
                            variables: {
                              id,
                              input: {
                                key: 'height',
                                value: [date_seen],
                                object_path: `/height/${height.index}/date_seen`,
                                operation: 'replace',
                              },
                            },
                          });
                        }
                      }}
                      textFieldProps={{
                        label: t_i18n('Date Seen'),
                        variant: 'standard',
                        helperText: (
                          <SubscriptionFocus
                            context={editContext}
                            fieldName={`${name}.${index}.date_seen`}
                          />
                        ),
                      }}
                    />
                  </div>
                  <IconButton
                    id="deleteHeader"
                    aria-label="Delete"
                    onClick={() => {
                      arrayHelpers.remove(index);
                      commitMutation({
                        ...defaultCommitMutation,
                        mutation: individualHeaderMutation,
                        variables: {
                          id,
                          input: {
                            key: 'height',
                            object_path: `/height/${height.index}`,
                            value: [],
                            operation: 'remove',
                          },
                        },
                      });
                    }}
                    size="large"
                    style={{ position: 'absolute', right: -10, top: 5 }}
                  >
                    <DeleteOutlined />
                  </IconButton>
                </div>
              );
            })}
            <Button
              size="small"
              startIcon={<AddOutlined />}
              variant="contained"
              color="primary"
              aria-label="Add"
              id="addHeader"
              onClick={() => {
                const newHeader = { measure: 0, date_seen: new Date().toISOString() };
                arrayHelpers.push(newHeader);
                commitMutation({
                  ...defaultCommitMutation,
                  mutation: individualHeaderMutation,
                  variables: {
                    id,
                    input: {
                      key: 'height',
                      value: [newHeader],
                      operation: 'add',
                    },
                  },
                });
              }}
              style={{ marginTop: (values?.length ?? 0) > 0 ? 20 : 0 }}
            >
              {t_i18n('Add query attribute')}
            </Button>
          </div>
        )}
      />
    </div>
  );
};

interface QueryAttributeFieldAddProps {
  id: string;
  name: string;
  values: {
    type: string,
    from: string,
    to: string,
    data_operation: string,
    state_operation: string,
    default: string,
    exposed: string
  }[];
  containerStyle: { marginTop: number; width: string };
  setFieldValue?: (name: string, value: unknown) => void;
}
export const QueryAttributeFieldAdd: FunctionComponent<QueryAttributeFieldAddProps> = ({
  name,
  values,
  containerStyle,
}): ReactElement => {
  const { t_i18n } = useFormatter();
  return (
    <div style={containerStyle}>
      <FieldArray
        name={name}
        render={(arrayHelpers) => (
          <>
            <div id="total_attributes">
              {values?.map((_, index) => (

                <Paper className={'paper-for-grid'} variant="outlined"
                  key={index}
                  style={{ marginTop: 20, padding: 20, width: '100%', position: 'relative' }}
                >
                  <div
                    style={{
                      paddingRight: 50,
                      display: 'grid',
                      gap: 20,
                      gridTemplateColumns: 'repeat(2, 1fr)',
                    }}
                  >
                    <Field component={SelectField}
                      variant="standard"
                      name={`${name}.${index}.type`}
                      label={t_i18n('Resolve from')}
                      fullWidth={true}
                      containerstyle={{ width: '100%' }}
                    >
                      <MenuItem value="data">{t_i18n('Data')}</MenuItem>
                      <MenuItem value="header">{t_i18n('Header')}</MenuItem>
                    </Field>

                    <Field component={SelectField}
                      variant="standard"
                      name={`${name}.${index}.exposed`}
                      label={t_i18n('Exposed attribute to')}
                      fullWidth={true}
                      containerstyle={{ width: '100%' }}
                    >
                      <MenuItem value="body">{t_i18n('Body')}</MenuItem>
                      <MenuItem value="query_param">{t_i18n('Query parameter')}</MenuItem>
                      <MenuItem value="header">{t_i18n('Header')}</MenuItem>
                    </Field>

                    <Field component={SelectField}
                      variant="standard"
                      name={`${name}.${index}.data_operation`}
                      label={t_i18n('Resolve operation')}
                      fullWidth={true}
                      containerstyle={{ width: '100%' }}
                    >
                      <MenuItem value="data">{t_i18n('Data')}</MenuItem>
                      <MenuItem value="count">{t_i18n('Count')}</MenuItem>
                    </Field>

                    <Field component={SelectField}
                      variant="standard"
                      name={`${name}.${index}.state_operation`}
                      label={t_i18n('State operation')}
                      fullWidth={true}
                      containerstyle={{ width: '100%' }}
                    >
                      <MenuItem value="replace">{t_i18n('Replace')}</MenuItem>
                      <MenuItem value="sum">{t_i18n('Sum')}</MenuItem>
                    </Field>

                    <Field
                      component={TextField}
                      variant="standard"
                      name={`${name}.${index}.from`}
                      label={t_i18n('Get from path')}
                    />
                    <Field
                      component={TextField}
                      variant="standard"
                      name={`${name}.${index}.to`}
                      label={t_i18n('To attribute name')}
                    />

                    <Field
                      component={TextField}
                      variant="standard"
                      name={`${name}.${index}.default`}
                      label={t_i18n('Default value')}
                    />

                  </div>
                  <IconButton
                    id="deleteHeader"
                    aria-label="Delete"
                    onClick={() => {
                      arrayHelpers.remove(index);
                    }}
                    size="large"
                    style={{ position: 'absolute', right: 0, top: 5 }}
                  >
                    <DeleteOutlined />
                  </IconButton>
                </Paper>
              ))}
              <Button
                size="small"
                startIcon={<AddOutlined />}
                variant="contained"
                color="primary"
                aria-label="Add"
                id="addHeader"
                onClick={() => {
                  arrayHelpers.push({
                    type: 'data',
                    from: '',
                    to: '',
                    data_operation: 'data',
                    state_operation: 'replace',
                    default: '',
                    exposed: 'body',
                  });
                }}
                style={{ marginTop: (values?.length ?? 0) > 0 ? 20 : 0 }}
              >
                {t_i18n('Add query attribute')}
              </Button>
            </div>
          </>
        )}
      />
    </div>
  );
};
