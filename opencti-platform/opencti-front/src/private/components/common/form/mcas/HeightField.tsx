import { FunctionComponent, ReactElement, useEffect, useState } from 'react';
import { Field, FieldArray } from 'formik';
import { IconButton, Typography } from '@mui/material';
import { Add, Delete } from '@mui/icons-material';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import convert from 'convert';
import { useFormatter } from '../../../../../components/i18n';
import { SubscriptionFocus } from '../../../../../components/Subscription';
import DatePickerField from '../../../../../components/DatePickerField';
import TextField from '../../../../../components/TextField';
import { commitLocalUpdate, commitMutation, defaultCommitMutation } from '../../../../../relay/environment';
import { HeightTupleInputValues } from './__generated__/HeightFieldIndividualMutation.graphql';
import { UnitSystems, validateUnitSystem } from '../../../../../utils/UnitSystems';

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
  setFieldValue: (name: string, value: any) => void,
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
  setFieldValue,
  containerStyle,
  editContext = [],
}): ReactElement => {
  const { t } = useFormatter();
  const [unitSystem, setUnitSystem] = useState<UnitSystems>();

  // Fetch default unit system
  useEffect(() => {
    if (!unitSystem) {
      commitLocalUpdate((store: RecordSourceSelectorProxy) => {
        const me = store.getRoot().getLinkedRecord('me');
        let selectedSystem;
        switch (me?.getValue('unit_system') as string) {
          case 'US': selectedSystem = UnitSystems.US;
            break;
          case 'Metric': selectedSystem = UnitSystems.Metric;
            break;
          default: selectedSystem = UnitSystems.Auto;
        }
        const language = me?.getValue('language') as string;
        const defaultUnitSystem = validateUnitSystem(
          selectedSystem,
          language,
        );
        setUnitSystem(defaultUnitSystem);
      });
    }
  }, []);

  const usingMetric = () => (unitSystem === UnitSystems.Metric);

  const valueInCm = (value: number) => {
    return usingMetric()
      ? value
      : convert(value, 'inch').to('centimeter');
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
                return (<div key={index}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name={`${name}.${index}.height_cm`}
                    // name={`${index}.height_cm`}
                    label={usingMetric()
                      ? t('Height (Centimeters)')
                      : t('Height (Inches)')}
                    enableReinitialize={true}
                    // value={usingMetric()
                    //   ? values[index].height_cm
                    //   : convert(Number(values[index].height_cm), 'centimeter').to('inch')
                    // }
                    onSubmit={(_: string, v: string) => {
                      const value = valueInCm(Number(v)) || 0;
                      console.log(`setting to ${value}`);
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
