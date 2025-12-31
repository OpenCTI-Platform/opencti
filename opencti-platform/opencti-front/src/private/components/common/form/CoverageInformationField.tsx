import React, { FunctionComponent, ReactElement } from 'react';
import { Field, FieldArray } from 'formik';
import Button from '@common/button/Button';
import { IconButton } from '@mui/material';
import { AddOutlined, DeleteOutlined } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import { graphql } from 'react-relay';
import OpenVocabField from '@components/common/form/OpenVocabField';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { GenericContext } from '../model/GenericContextModel';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import { isEmptyField, isNotEmptyField } from '../../../../utils/utils';

export const coverageEntityInformationMutation = graphql`
  mutation CoverageInformationFieldEntityMutation($id: ID!, $input: [EditInput]!) {
    securityCoverageFieldPatch(id: $id, input: $input) {
      coverage_information {
        coverage_name
        coverage_score
      }
    }
  }
`;

export const coverageRelationInformationMutation = graphql`
  mutation CoverageInformationFieldRelationMutation($id: ID!, $input: [EditInput]!) {
      stixCoreRelationshipEdit(id: $id) {
          fieldPatch(input: $input) {
              coverage_information {
                  coverage_name
                  coverage_score
              }
          }
    }
  }
`;

interface CoverageInformationInput {
  coverage_name: string;
  coverage_score: number | string;
}

interface CoverageInformationFieldAddProps {
  name: string;
  values: CoverageInformationInput[];
  containerStyle?: React.CSSProperties;
  setFieldValue?: (name: string, value: unknown) => void;
}

interface CoverageInformationFieldEditProps {
  id: string;
  name: string;
  mode: 'entity' | 'relation';
  values: ReadonlyArray<{
    readonly coverage_name: string;
    readonly coverage_score: number;
  }> | null | undefined;
  containerStyle?: React.CSSProperties;
  editContext?: readonly (GenericContext | null)[] | null;
}

export const CoverageInformationFieldAdd: FunctionComponent<CoverageInformationFieldAddProps> = ({
  name,
  values,
  containerStyle,
}): ReactElement => {
  const { t_i18n } = useFormatter();

  const disabledOptions = values
    ?.map((v) => v.coverage_name)
    .filter((coverageName) => coverageName !== '');

  return (
    <div style={{ ...fieldSpacingContainerStyle, ...containerStyle }}>
      <Typography variant="h4" gutterBottom>
        {t_i18n('Coverage Information')}
      </Typography>
      <FieldArray
        name={name}
        render={(arrayHelpers) => (
          <>
            <div>
              {values?.map((_, index) => (
                <div
                  key={index}
                  style={{
                    marginTop: index === 0 ? 10 : 20,
                    width: '100%',
                    position: 'relative',
                    paddingRight: 50,
                  }}
                >
                  <div
                    style={{
                      display: 'grid',
                      gap: 20,
                      gridTemplateColumns: '1fr 1fr',
                    }}
                  >
                    <OpenVocabField
                      label={t_i18n('Coverage name')}
                      type="coverage_ov"
                      name={`${name}.${index}.coverage_name`}
                      required={true}
                      onChange={(__, value) => {
                        arrayHelpers.replace(index, { ...values[index], coverage_name: value.toString() });
                      }}
                      disabledOptions={disabledOptions}
                      containerStyle={{ marginTop: 3, width: '100%' }}
                      multiple={false}
                    />
                    <Field
                      component={TextField}
                      variant="standard"
                      name={`${name}.${index}.coverage_score`}
                      label={t_i18n('Coverage score (0-100)')}
                      type="number"
                      fullWidth
                      required
                      slotProps={{
                        input: {
                          inputProps: {
                            min: 0,
                            max: 100,
                          },
                        },
                      }}
                    />
                  </div>
                  <IconButton
                    id={`deleteCoverageInfo_${index}`}
                    aria-label="Delete"
                    onClick={() => {
                      arrayHelpers.remove(index);
                    }}
                    style={{ position: 'absolute', right: -10, top: 5 }}
                  >
                    <DeleteOutlined />
                  </IconButton>
                </div>
              ))}
              <Button
                size="small"
                startIcon={<AddOutlined />}
                aria-label="Add"
                id="addCoverageInfo"
                onClick={() => {
                  arrayHelpers.push({ coverage_name: '', coverage_score: '' });
                }}
                style={{ marginTop: 20 }}
              >
                {t_i18n('Add coverage metric')}
              </Button>
            </div>
          </>
        )}
      />
    </div>
  );
};

export const CoverageInformationFieldEdit: FunctionComponent<CoverageInformationFieldEditProps> = ({
  id,
  name,
  values,
  containerStyle,
  mode,
  editContext = [],
}): ReactElement => {
  const { t_i18n } = useFormatter();
  const coverageInformationMutation = mode === 'entity'
    ? coverageEntityInformationMutation : coverageRelationInformationMutation;

  const disabledOptions = values
    ?.map((v) => v.coverage_name)
    .filter((coverageName) => coverageName !== '');

  return (
    <div style={{ ...fieldSpacingContainerStyle, ...containerStyle }}>
      <Typography variant="h4" gutterBottom>
        {t_i18n('Coverage Information')}
      </Typography>
      <FieldArray
        name={name}
        render={(arrayHelpers) => (
          <>
            <div>
              {(values ?? []).map((__, index) => (
                <div
                  key={index}
                  style={{
                    marginTop: index === 0 ? 10 : 20,
                    width: '100%',
                    position: 'relative',
                    paddingRight: 50,
                  }}
                >
                  <div style={{ display: 'grid', gap: 20, gridTemplateColumns: '1fr 1fr' }}>
                    <OpenVocabField
                      label={t_i18n('Coverage name')}
                      type="coverage_ov"
                      name={`${name}.${index}.coverage_name`}
                      required={true}
                      disabledOptions={disabledOptions}
                      onChange={(_: string, value) => {
                        const isCreation = isEmptyField(values?.[index]?.coverage_name);
                        if (isNotEmptyField(value)) {
                          if (isCreation) {
                            commitMutation({
                              ...defaultCommitMutation,
                              mutation: coverageInformationMutation,
                              variables: {
                                id,
                                input: {
                                  key: 'coverage_information',
                                  value: [{ coverage_name: value.toString(), coverage_score: values?.[index]?.coverage_score }],
                                  operation: 'add',
                                },
                              },
                            });
                          } else {
                            commitMutation({
                              ...defaultCommitMutation,
                              mutation: coverageInformationMutation,
                              variables: {
                                id,
                                input: {
                                  key: 'coverage_information',
                                  value: [value.toString()],
                                  object_path: `/coverage_information/${index}/coverage_name`,
                                  operation: 'replace',
                                },
                              },
                            });
                          }
                        }
                      }}
                      containerStyle={{ marginTop: 3, width: '100%' }}
                      multiple={false}
                    />
                    <Field
                      component={TextField}
                      variant="standard"
                      name={`${name}.${index}.coverage_score`}
                      label={t_i18n('Coverage score (0-100)')}
                      type="number"
                      fullWidth
                      required
                      slotProps={{
                        input: {
                          inputProps: {
                            min: 0,
                            max: 100,
                          },
                        },
                      }}
                      onSubmit={(_: string, score: string) => {
                        if (isNotEmptyField(score)) {
                          commitMutation({
                            ...defaultCommitMutation,
                            mutation: coverageInformationMutation,
                            variables: {
                              id,
                              input: {
                                key: 'coverage_information',
                                value: [parseInt(score, 10)],
                                object_path: `/coverage_information/${index}/coverage_score`,
                                operation: 'replace',
                              },
                            },
                          });
                        }
                      }}
                      helperText={(
                        <SubscriptionFocus
                          context={editContext}
                          fieldName={`${name}.${index}.coverage_score`}
                        />
                      )}
                    />
                  </div>
                  {(values?.length ?? 0) > 0 && (
                    <IconButton
                      id={`deleteCoverageInfo_${index}`}
                      aria-label="Delete"
                      onClick={() => {
                        arrayHelpers.remove(index);
                        commitMutation({
                          ...defaultCommitMutation,
                          mutation: coverageInformationMutation,
                          variables: {
                            id,
                            input: {
                              key: 'coverage_information',
                              object_path: `/coverage_information/${index}`,
                              value: [],
                              operation: 'remove',
                            },
                          },
                        });
                      }}
                      style={{ position: 'absolute', right: -10, top: 5 }}
                    >
                      <DeleteOutlined />
                    </IconButton>
                  )}
                </div>
              ))}
              <Button
                size="small"
                startIcon={<AddOutlined />}
                aria-label="Add"
                id="addCoverageInfo"
                onClick={() => {
                  const newCoverage = { coverage_name: '', coverage_score: 0 };
                  arrayHelpers.push(newCoverage);
                }}
                style={{ marginTop: (values?.length ?? 0) > 0 ? 20 : 0 }}
              >
                {t_i18n('Add coverage metric')}
              </Button>
            </div>
          </>
        )}
      />
    </div>
  );
};
