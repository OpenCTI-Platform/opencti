import React, { FunctionComponent, ReactElement } from 'react';
import { Field, FieldArray } from 'formik';
import { IconButton } from '@mui/material';
import { AddOutlined, DeleteOutlined } from '@mui/icons-material';
import { graphql } from 'react-relay';
import { MeasureInput } from '@components/threats/threat_actors_individual/__generated__/ThreatActorIndividualCreationMutation.graphql';
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
  name: string;
  values: MeasureInput[];
  containerStyle: { marginTop: number; width: string };
  setFieldValue?: (name: string, value: unknown) => void;
}
export const WeightFieldAdd: FunctionComponent<WeightFieldAddProps> = ({
  name,
  values,
  containerStyle,
}): ReactElement => {
  const { t } = useFormatter();
  const { weightPrimaryUnit } = useUserMetric();
  return (
    <div style={containerStyle}>
      <FieldArray
        name={name}
        render={(arrayHelpers) => (
          <>
            {values?.map(({ date_seen }, index) => (
              <div
                key={date_seen}
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
                    name={`${name}.${index}.measure`}
                    label={t(`Weight (${weightPrimaryUnit})`)}
                    type="number"
                    InputProps={{ inputProps: { min: 0 } }}
                  />
                  <Field
                    component={DatePickerField}
                    name={`${name}.${index}.date_seen`}
                    TextFieldProps={{
                      label: t('Date Seen'),
                      variant: 'standard',
                    }}
                    type="date"
                  />
                </div>
                <IconButton
                  id="deleteHeight"
                  aria-label="Delete"
                  onClick={() => {
                    arrayHelpers.remove(index);
                  }}
                  size="large"
                  style={{ position: 'absolute', right: -10, top: 5 }}
                >
                  <DeleteOutlined />
                </IconButton>
              </div>
            ))}
            <Button
              size="small"
              startIcon={<AddOutlined />}
              variant="contained"
              color="primary"
              aria-label="Add"
              id="addHeight"
              onClick={() => {
                arrayHelpers.push({ date_seen: null });
              }}
              style={{ marginTop: (values?.length ?? 0) > 0 ? 20 : 0 }}
            >
              {t('Add a weight')}
            </Button>
          </>
        )}
      />
    </div>
  );
};

interface WeightFieldEditProps {
  id: string;
  name: string;
  values: ThreatActorIndividualEditionBiographics_ThreatActorIndividual$data['weight'];
  containerStyle: {
    marginTop: number;
    width: string;
  };
  setFieldValue?: (name: string, value: unknown) => void;
  editContext?:
  | readonly {
    readonly focusOn: string | null;
    readonly name: string;
  }[]
  | null;
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
  return (
    <div style={containerStyle}>
      <FieldArray
        name={name}
        render={(arrayHelpers) => (
          <>
            {(values ?? []).map((weight, index) => {
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
                              object_path: `weight[${weight.index}].measure`,
                              operation: 'replace',
                            },
                          },
                        });
                      }}
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
                              object_path: `weight[${weight.index}].date_seen`,
                              operation: 'replace',
                            },
                          },
                        });
                      }}
                      TextFieldProps={{
                        label: t('Date Seen'),
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
                    id="deleteWeight"
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
                            object_path: `weight[${weight.index}]`,
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
              id="addHeight"
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
              }}
              style={{ marginTop: (values?.length ?? 0) > 0 ? 20 : 0 }}
            >
              {t('Add a weight')}
            </Button>
          </>
        )}
      />
    </div>
  );
};
