import { FunctionComponent, ReactElement } from 'react';
import { Field, FieldArray } from 'formik';
import { IconButton, Typography } from '@mui/material';
import { Add, Delete } from '@mui/icons-material';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../../../components/i18n';
import { SubscriptionFocus } from '../../../../../components/Subscription';
import DatePickerField from '../../../../../components/DatePickerField';
import TextField from '../../../../../components/TextField';
import { commitMutation, defaultCommitMutation } from '../../../../../relay/environment';
import { WeightTupleInputValues } from './__generated__/WeightFieldIndividualMutation.graphql';

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
  editContext = [],
}): ReactElement => {
  const { t } = useFormatter();

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
              {values.map(({weight_kg, date_seen }: WeightTupleInputValues, index) => (
                <div key={date_seen}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name={`${name}.${index}.weight_kg`}
                    label={t('Weight (Kilograms)')}
                    InputLabelProps={{
                      shrink: true,
                    }}
                    onChange={(_: string, v: string) => {
                      commitMutation({
                        ...defaultCommitMutation,
                        mutation: individualWeightMutation,
                        variables: {
                          id,
                          input: {
                            values: [{
                              weight_kg: Number(v) || 0,
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
              ))}
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
                    name={`${name}.${index}.weight_kg`}
                    label={t('Weight (Kilograms)')}
                    style={{ marginRight: 20 }}
                    type='number'
                    InputLabelProps={{
                      shrink: true,
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
