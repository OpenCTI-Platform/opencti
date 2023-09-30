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
import { HeightTupleInputValues } from './__generated__/HeightFieldIndividualMutation.graphql';
import { UnitSystems } from '../../../../../utils/UnitSystems';
import useAuth from '../../../../../utils/hooks/useAuth';

export const individualHeightMutation = graphql`
  mutation HeightFieldIndividualMutation($id: ID!, $input: HeightTupleInput!) {
    threatActorIndividualHeightEdit(id: $id, input: $input, sort: false) {
      height {
        height_cm
        date_seen
      }
    }
  }
`;

interface HeightFieldProps {
  name: string,
  label: string,
  variant: string,
  id: string,
  values: HeightTupleInputValues[],
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

const HeightField: FunctionComponent<HeightFieldProps> = ({
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
  switch (me.unit_system) {
    case 'US': unitSystem = UnitSystems.US;
      break;
    case 'Metric': unitSystem = UnitSystems.Metric;
      break;
    default:
  }

  const usingMetric = () => (unitSystem === UnitSystems.Metric);

  const valueInCm = (value: number | string) => {
    return usingMetric()
      ? Number(value)
      : convert(Number(value), 'inch').to('centimeter');
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
            <div id={'total_height_read'}>
              {values.map((
                {
                  height_cm,
                  date_seen,
                }: HeightTupleInputValues,
                index,
              ) => {
                const fieldName = `${name}.${index}.height_${usingMetric() ? 'cm' : 'in'}`;
                return (<div key={index}>
                  <Field
                    component={TextField}
                    variant="standard"
                    type="number"
                    InputProps={{ inputProps: { min: 0 } }}
                    name={fieldName}
                    label={usingMetric()
                      ? t('Height (Centimeters)')
                      : t('Height (Inches)')}
                    onSubmit={(_: string, v: string) => {
                      const value = valueInCm(v);
                      commitMutation({
                        ...defaultCommitMutation,
                        mutation: individualHeightMutation,
                        variables: {
                          id,
                          input: {
                            values: [{
                              height_cm: value,
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
                    id={`height_date_${index}`}
                    name={`${name}.${index}.date_seen`}
                    onSubmit={(_: string, v: string) => {
                      commitMutation({
                        ...defaultCommitMutation,
                        mutation: individualHeightMutation,
                        variables: {
                          id,
                          input: {
                            values: [{
                              height_cm,
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
                    id= "deleteHeight"
                    aria-label="Delete"
                    onClick={() => {
                      arrayHelpers.remove(index);
                      commitMutation({
                        ...defaultCommitMutation,
                        mutation: individualHeightMutation,
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
                id="addHeight"
                color="primary"
                onClick={() => {
                  arrayHelpers.push({});
                  commitMutation({
                    ...defaultCommitMutation,
                    mutation: individualHeightMutation,
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
                <b style={{ fontSize: 12 }}>{t('Add a height')}</b> <Add />
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
            <div id={'total_height_read'}>
              {values?.map((_, index) => (
                <div key={index}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name={`${name}.${index}.height_${usingMetric() ? 'cm' : 'in'}`}
                    label={usingMetric()
                      ? t('Height (Centimeters)')
                      : t('Height (Inches)')
                    }
                    style={{ marginRight: 20 }}
                    type='number'
                    InputProps={{ inputProps: { min: 0 } }}
                    onSubmit={(__: string, v: string) => {
                      const value = valueInCm(v);
                      if (setFieldValue) setFieldValue(`${name}.${index}.height_cm`, value);
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
                    id="deleteHeight"
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
                id="addHeight"
                color="primary"
                onClick={() => {
                  arrayHelpers.push({ date_seen: null });
                }}
              >
                <b style={{ fontSize: 12 }}>{t('Add a height')}</b> <Add />
              </IconButton>
            </div>
          )}
        ></FieldArray>
      </div>;
};

export default HeightField;
