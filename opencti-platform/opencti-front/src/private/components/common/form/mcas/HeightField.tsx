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
import { HeightTupleInputValues } from './__generated__/HeightFieldIndividualMutation.graphql';

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
            <div id={'total_height_read'}>
              {values.map((
                {
                  height_cm,
                  date_seen,
                }: HeightTupleInputValues,
                index,
              ) => (
                <div key={index}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name={`${name}.${index}.height_cm`}
                    label={t('Height (Centimeters)')}
                    InputLabelProps={{
                      shrink: true,
                    }}
                    onChange={(_: string, v: string) => {
                      commitMutation({
                        ...defaultCommitMutation,
                        mutation: individualHeightMutation,
                        variables: {
                          id,
                          input: {
                            values: [{
                              height_cm: Number(v) || 0,
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
              ))}
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
                    name={`${name}.${index}.height_cm`}
                    label={t('Height (Centimeters)')}
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
