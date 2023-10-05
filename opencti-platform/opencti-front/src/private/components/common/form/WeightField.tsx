import { FunctionComponent, ReactElement } from 'react';
import { Field, FieldArray } from 'formik';
import { IconButton } from '@mui/material';
import { Add, Delete } from '@mui/icons-material';
import { graphql } from 'react-relay';
import {
  MeasureInput,
} from '@components/threats/threat_actors_individual/__generated__/ThreatActorIndividualCreationMutation.graphql';
import {
  ThreatActorIndividualEditionBiographics_ThreatActorIndividual$data,
} from '@components/threats/threat_actors_individual/__generated__/ThreatActorIndividualEditionBiographics_ThreatActorIndividual.graphql';
import Button from '@mui/material/Button';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionFocus } from '../../../../components/Subscription';
import DatePickerField from '../../../../components/DatePickerField';
import TextField from '../../../../components/TextField';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import useUserMetric from '../../../../utils/hooks/useUserMetric';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

export const individualWeightMutation = graphql`
  mutation WeightFieldIndividualMutation($id: ID!, $input: [EditInput]!) {
    threatActorIndividualFieldPatch(id: $id, input: $input) {
      weight {
        measure
        date_seen
        index
      }
    }
  }
`;

interface WeightFieldAddProps {
  name: string,
  values: MeasureInput[],
  containerStyle: { marginTop: number; width: string; },
  setFieldValue?: (name: string, value: unknown) => void,
}
export const WeightFieldAdd: FunctionComponent<WeightFieldAddProps> = ({
  name,
  values,
  containerStyle,
}): ReactElement => {
  const { t } = useFormatter();
  const { weightPrimaryUnit } = useUserMetric();
  return <div style={containerStyle}>
            <FieldArray
                name={name}
                render={(arrayHelpers) => (
                    <div>
                        <Button size="small" startIcon={<Add />} variant="contained" color="primary" aria-label="Add" id="addHeight"
                                onClick={() => {
                                  arrayHelpers.push({ date_seen: null });
                                }}>
                            {t('Add a weight')}
                        </Button>
                        {values?.map(({ date_seen }, index) => (
                            <div key={date_seen} style={fieldSpacingContainerStyle}>
                                <Field
                                    component={TextField}
                                    variant="standard"
                                    name={`${name}.${index}.measure`}
                                    label={t(`Weight (${weightPrimaryUnit})`)}
                                    style={{ marginRight: 20, width: '40%' }}
                                    type='number'
                                    InputProps={{ inputProps: { min: 0 } }}
                                />
                                <Field
                                    component={DatePickerField}
                                    name={`${name}.${index}.date_seen`}
                                    TextFieldProps={{
                                      label: t('Date Seen'),
                                      variant: 'standard',
                                      style: { width: '40%' },
                                    }}
                                    type='date'
                                />
                                <IconButton
                                    id='deleteWeight'
                                    aria-label="Delete"
                                    onClick={() => {
                                      arrayHelpers.remove(index);
                                    }}
                                    size="large"
                                    style={{ marginTop: 5 }}
                                >
                                    <Delete />
                                </IconButton>
                            </div>
                        ))}
                    </div>
                )}
            ></FieldArray>
        </div>;
};

interface WeightFieldEditProps {
  id: string,
  name: string,
  values: ThreatActorIndividualEditionBiographics_ThreatActorIndividual$data['weight'],
  containerStyle: {
    marginTop: number;
    width: string;
  },
  setFieldValue?: (name: string, value: unknown) => void,
  editContext?: readonly {
    readonly focusOn: string | null;
    readonly name: string;
  }[] | null,
}
export const WeightFieldEdit: FunctionComponent<WeightFieldEditProps> = ({
  id,
  name,
  values,
  containerStyle,
  editContext = [],
}): ReactElement => {
  const { t } = useFormatter();
  const { weightPrimaryUnit, weightToPivotFormat } = useUserMetric();
  return <div style={containerStyle}>
        <Button size="small" startIcon={<Add />} variant="contained" color="primary" aria-label="Add" id="addHeight"
                onClick={() => {
                  commitMutation({
                    ...defaultCommitMutation,
                    mutation: individualWeightMutation,
                    variables: {
                      id,
                      input: {
                        key: 'weight',
                        value: [{ measure: null, date_seen: null }],
                        operation: 'add',
                      },
                    },
                  });
                }}>
            {t('Add a weight')}
        </Button>
        <FieldArray
          name={name}
          render={(arrayHelpers) => (
            <div>
              {(values ?? []).map((weight, index) => {
                return (<div key={index} style={fieldSpacingContainerStyle}>
                  <Field
                    component={TextField}
                    variant="standard"
                    type="number"
                    InputProps={{ inputProps: { min: 0 } }}
                    name={`${name}.${index}.measure`}
                    label={t(`Weight (${weightPrimaryUnit})`)}
                    onSubmit={(_: string, measure: string) => {
                      commitMutation({
                        ...defaultCommitMutation,
                        mutation: individualWeightMutation,
                        variables: {
                          id,
                          input: {
                            key: 'weight',
                            value: [weightToPivotFormat(measure)],
                            object_path: `[${weight.index}].measure`,
                            operation: 'replace',
                          },
                        },
                      });
                    }}
                    style={{ marginRight: 20, width: '40%' }}
                  />
                  <Field
                    component={DatePickerField}
                    name={`${name}.${index}.date_seen`}
                    id={`weight_date_${index}`}
                    onSubmit={(_: string, date_seen: string) => {
                      commitMutation({
                        ...defaultCommitMutation,
                        mutation: individualWeightMutation,
                        variables: {
                          id,
                          input: {
                            key: 'weight',
                            value: [date_seen],
                            object_path: `[${weight.index}].date_seen`,
                            operation: 'replace',
                          },
                        },
                      });
                    }}
                    TextFieldProps={{
                      label: t('Date Seen'),
                      variant: 'standard',
                      style: { width: '40%' },
                      helperText: (
                        <SubscriptionFocus
                          context={editContext}
                          fieldName={`${name}.${index}.date_seen`}
                        />
                      ),
                    }}
                  />
                  <IconButton
                    id='deleteWeight'
                    aria-label="Delete"
                    onClick={() => {
                      arrayHelpers.remove(index);
                      commitMutation({
                        ...defaultCommitMutation,
                        mutation: individualWeightMutation,
                        variables: {
                          id,
                          input: {
                            key: 'weight',
                            object_path: `[${weight.index}]`,
                            value: [],
                            operation: 'remove',
                          },
                        },
                      });
                    }}
                    size="large"
                    style={{ marginTop: 5 }}
                  >
                    <Delete />
                  </IconButton>
                </div>
                );
              })}
            </div>
          )}
        ></FieldArray>
      </div>;
};
