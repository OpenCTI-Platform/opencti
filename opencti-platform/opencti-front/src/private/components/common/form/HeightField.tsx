import { FunctionComponent, ReactElement } from 'react';
import { Field, FieldArray } from 'formik';
import { IconButton, Typography } from '@mui/material';
import { Add, Delete } from '@mui/icons-material';
import { graphql } from 'react-relay';
import {
  ThreatActorIndividualEditionBiographics_ThreatActorIndividual$data,
} from '@components/threats/threat_actors_individual/__generated__/ThreatActorIndividualEditionBiographics_ThreatActorIndividual.graphql';
import {
  MeasureInput,
} from '@components/threats/threat_actors_individual/__generated__/ThreatActorIndividualCreationMutation.graphql';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionFocus } from '../../../../components/Subscription';
import DatePickerField from '../../../../components/DatePickerField';
import TextField from '../../../../components/TextField';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import useUserMetric from '../../../../utils/hooks/useUserMetric';

export const individualHeightMutation = graphql`
  mutation HeightFieldIndividualMutation($id: ID!, $input: [EditInput]!) {
    threatActorIndividualFieldPatch(id: $id, input: $input) {
      height {
        index
        measure
        date_seen
      }
    }
  }
`;

interface HeightFieldEditProps {
  name: string,
  label: string,
  id: string,
  values: ThreatActorIndividualEditionBiographics_ThreatActorIndividual$data['height'],
  containerStyle: { marginTop: number; width: string; },
  setFieldValue?: (name: string, value: unknown) => void,
  editContext?: readonly {
    readonly focusOn: string | null;
    readonly name: string;
  }[] | null,
}
export const HeightFieldEdit: FunctionComponent<HeightFieldEditProps> = ({
  name,
  label,
  id,
  values,
  containerStyle,
  editContext = [],
}): ReactElement => {
  const { t } = useFormatter();
  const { lengthPrimaryUnit, heightToPivotFormat } = useUserMetric();
  return <div style={containerStyle}>
        <Typography variant="h3" gutterBottom={true} style={{ float: 'left', color: 'rgb(0, 177, 255)' }}>
          {label}
        </Typography>
        <br />
        <FieldArray
          name={name}
          render={(arrayHelpers) => (
            <div id={'total_height_read'}>
              {(values ?? []).map((height, index) => {
                return (<div key={index}>
                  <Field
                    component={TextField}
                    variant="standard"
                    type="number"
                    InputProps={{ inputProps: { min: 0 } }}
                    name={`${name}.${index}.measure`}
                    label={t(`Height (${lengthPrimaryUnit})`)}
                    onSubmit={(_: string, measure: string) => {
                      commitMutation({
                        ...defaultCommitMutation,
                        mutation: individualHeightMutation,
                        variables: {
                          id,
                          input: {
                            key: 'height',
                            value: [heightToPivotFormat(measure)],
                            object_path: `[${height.index}].measure`,
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
                    onSubmit={(_: string, date_seen: string) => {
                      commitMutation({
                        ...defaultCommitMutation,
                        mutation: individualHeightMutation,
                        variables: {
                          id,
                          input: {
                            key: 'height',
                            value: [date_seen],
                            object_path: `[${height.index}].date_seen`,
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
                            key: 'height',
                            value: `[${height.index}]`,
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
                  commitMutation({
                    ...defaultCommitMutation,
                    mutation: individualHeightMutation,
                    variables: {
                      id,
                      input: {
                        key: 'height',
                        value: [{ measure: null, date_seen: null }],
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
      </div>;
};

interface HeightFieldAddProps {
  id: string,
  name: string,
  label: string,
  values: MeasureInput[],
  containerStyle: { marginTop: number; width: string; },
  setFieldValue?: (name: string, value: unknown) => void,
}
export const HeightFieldAdd: FunctionComponent<HeightFieldAddProps> = ({
  name,
  label,
  values,
  containerStyle,
}): ReactElement => {
  const { t } = useFormatter();
  const { lengthPrimaryUnit } = useUserMetric();

  return <div style={containerStyle}>
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
                                    name={`${name}.${index}.measure`}
                                    label={t(`Height (${lengthPrimaryUnit})`)}
                                    style={{ marginRight: 20 }}
                                    type='number'
                                    InputProps={{ inputProps: { min: 0 } }}
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
