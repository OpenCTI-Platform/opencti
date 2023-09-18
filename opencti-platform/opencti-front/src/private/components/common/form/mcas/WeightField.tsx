import { FunctionComponent, ReactElement } from 'react';
import { Field, FieldArray } from 'formik';
import { IconButton, Typography } from '@mui/material';
import { Add, Delete } from '@mui/icons-material';
import { graphql } from 'react-relay';
import convert from 'convert';
import { useFormatter } from '../../../../../components/i18n';
import { SubscriptionFocus } from '../../../../../components/Subscription';
import DatePickerField from '../../../../../components/DatePickerField';
import TextField from '../../../../../components/TextField';
import { commitMutation, defaultCommitMutation } from '../../../../../relay/environment';
import { WeightTupleInputValues } from './__generated__/WeightFieldIndividualMutation.graphql';
import { UnitSystems } from '../../../../../utils/UnitSystems';
import useAuth from '../../../../../utils/hooks/useAuth';

export const individualWeightMutation = graphql`
  mutation WeightFieldIndividualMutation($id: ID!, $input: WeightTupleInput!) {
    threatActorIndividualWeightEdit(id: $id, input: $input, sort: false) {
      weight {
        weight_kg
        date_seen
      }
    }
  }
`;

interface WeightFieldProps {
  name: string,
  label: string,
  variant: string,
  id: string,
  values: WeightTupleInputValues[],
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

const WeightField: FunctionComponent<WeightFieldProps> = ({
  name,
  label,
  variant,
  id,
  values,
  containerStyle,
  setFieldValue,
  editContext = [],
}): ReactElement => {
  const { t } = useFormatter();
  const { me } = useAuth();
  let unitSystem = UnitSystems.Auto;
  switch (me?.unit_system) {
    case 'US': unitSystem = UnitSystems.US;
      break;
    case 'Metric': unitSystem = UnitSystems.Metric;
      break;
    default:
  }

  const usingMetric = () => (unitSystem === UnitSystems.Metric);

  const valueInKg = (value: number | string) => {
    return usingMetric()
      ? Number(value)
      : convert(Number(value), 'pound').to('kilogram');
  };

  return variant === 'edit'
    ? <div style={containerStyle}>
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ float: 'left', color: 'rgb(0, 177, 255)' }}
        >
          {label}
        </Typography>
        <br />
        <FieldArray
          name={name}
          render={(arrayHelpers) => (
            <div>
              {values.map(({ weight_kg, date_seen }: WeightTupleInputValues, index) => {
                const fieldName = `${name}.${index}.weight_${usingMetric() ? 'kg' : 'lb'}`;
                return (<div key={date_seen}>
                  <Field
                    component={TextField}
                    variant="standard"
                    type="number"
                    InputProps={{ inputProps: { min: 0 } }}
                    name={fieldName}
                    label={usingMetric()
                      ? t('Weight (Kilograms)')
                      : t('Weight (Pounds)')
                    }
                    onSubmit={(_: string, v: string) => {
                      const value = valueInKg(v);
                      commitMutation({
                        ...defaultCommitMutation,
                        mutation: individualWeightMutation,
                        variables: {
                          id,
                          input: {
                            values: [{
                              weight_kg: value,
                              date_seen,
                            }],
                            index,
                            operation: 'replace',
                          },
                        },
                      });
                    }}
                    style={{ marginRight: 20 }}
                  />
                  <Field
                    component={DatePickerField}
                    name={`${name}.${index}.date_seen`}
                    id={`weight_date_${index}`}
                    onSubmit={(_: string, v: string) => {
                      commitMutation({
                        ...defaultCommitMutation,
                        mutation: individualWeightMutation,
                        variables: {
                          id,
                          input: {
                            values: [{
                              weight_kg,
                              date_seen: v,
                            }],
                            index,
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
                            index,
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
              <IconButton
                aria-label="Add"
                id="addWeight"
                color="primary"
                onClick={() => {
                  arrayHelpers.push({});
                  commitMutation({
                    ...defaultCommitMutation,
                    mutation: individualWeightMutation,
                    variables: {
                      id,
                      input: {
                        values: [{}],
                        operation: 'add',
                      },
                    },
                  });
                }}
              >
                <b style={{ fontSize: 12 }}>{t('Add a weight')}</b> <Add />
              </IconButton>
            </div>
          )}
        ></FieldArray>
      </div>
    : <div style={containerStyle}>
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ float: 'left', color: 'rgb(0, 177, 255)' }}
        >
          {label}
        </Typography>
        <br />
        <FieldArray
          name={name}
          render={(arrayHelpers) => (
            <div>
              {values?.map(({ date_seen }, index) => (
                <div key={date_seen}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name={`${name}.${index}.weight_${usingMetric() ? 'kg' : 'lb'}`}
                    label={usingMetric()
                      ? t('Weight (Kilograms)')
                      : t('Weight (Pounds)')
                    }
                    style={{ marginRight: 20 }}
                    type='number'
                    InputProps={{ inputProps: { min: 0 } }}
                    onSubmit={(_: string, v: string) => {
                      const value = valueInKg(v);
                      if (setFieldValue) setFieldValue(`${name}.${index}.weight_kg`, value);
                    }}
                  />
                  <Field
                    component={DatePickerField}
                    name={`${name}.${index}.date_seen`}
                    TextFieldProps={{
                      label: t('Date Seen'),
                      variant: 'standard',
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
              <IconButton
                aria-label="Add"
                id ="addWeight"
                color="primary"
                onClick={() => {
                  arrayHelpers.push({ date_seen: null });
                }}
              >
                <b style={{ fontSize: 12 }}>{t('Add a weight')}</b> <Add />
              </IconButton>
            </div>
          )}
        ></FieldArray>
      </div>;
};

export default WeightField;
