import { Field, FieldArray, FieldProps } from 'formik';
import Button from '@common/button/Button';
import { IconButton } from '@filigran/design-system';
import { DeleteOutlined } from '@mui/icons-material';
import { graphql } from 'react-relay';
import OpenVocabField from '@components/common/form/OpenVocabField';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { GenericContext } from '../model/GenericContextModel';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { CoverageInformation } from '@components/analyses/security_coverages/SecurityCoverage-types';
import { FormGroup, FormLabel, Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Theme } from '../../../../components/Theme';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { CoverageInformationFieldEntityMutation } from './__generated__/CoverageInformationFieldEntityMutation.graphql';
import { useEffect } from 'react';
import useDebounceCallback from '../../../../utils/hooks/useDebounceCallback';

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

interface CoverageInformationFieldProps extends FieldProps<CoverageInformation[]> {
  id?: string;
  mutationType?: 'entity' | 'relation';
  editContext?: readonly (GenericContext | null)[] | null;
}

const CoverageInformationField = ({
  form: { getFieldMeta, submitCount, setFieldTouched, setFieldValue },
  field: { value, name },
  mutationType,
  editContext,
  id,
}: CoverageInformationFieldProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { error, touched } = getFieldMeta(name);
  const [entityMutation] = useApiMutation<CoverageInformationFieldEntityMutation>(coverageEntityInformationMutation);
  const [relationshipMutation] = useApiMutation<CoverageInformationFieldEntityMutation>(coverageRelationInformationMutation);

  const inEdition = !!id;
  const showError = !!error && typeof error === 'string' && (touched || submitCount > 0);
  const coverageInformationMutation = mutationType === 'entity' ? entityMutation : relationshipMutation;

  const disabledOptions = value
    ?.map((v) => v.coverage_name)
    .filter((coverageName) => coverageName !== '');

  // Debounce is used to be sure that validation by Formik has been executed after the value changes.
  // Otherwise we could end up sending an update of an invalid config because of how react states work.
  const submitUpdate = useDebounceCallback((val: typeof value, err: typeof error) => {
    if (inEdition && !err && touched) {
      coverageInformationMutation({
        variables: {
          id,
          input: [{
            key: 'coverage_information',
            value: val,
            operation: 'replace',
          }],
        },
      });
    }
  }, 200);
  useEffect(() => {
    if (inEdition) submitUpdate(value, error);
  }, [value, error]);

  return (
    <div style={{ ...fieldSpacingContainerStyle }}>
      <FormGroup>
        <FormLabel
          required
          error={showError}
          sx={{ mb: showError ? 0 : 1 }}
        >
          {t_i18n('Coverage Information')}
        </FormLabel>
        {showError && (
          <Typography
            variant="body2"
            sx={{
              color: theme.palette.error.main,
              mb: 1,
            }}
          >
            {error}
          </Typography>
        )}
        <FieldArray
          name={name}
          render={(arrayHelpers) => (
            <div>
              {value?.map((_, index) => (
                <div
                  key={index}
                  style={{
                    marginBottom: 8,
                    width: '100%',
                    position: 'relative',
                    display: 'flex',
                    gap: 8,
                  }}
                >
                  <div
                    style={{
                      display: 'grid',
                      gap: 12,
                      gridTemplateColumns: '1fr 1fr',
                      flex: 1,
                    }}
                  >
                    <OpenVocabField
                      label={t_i18n('Coverage name')}
                      type="coverage_ov"
                      name={`${name}.${index}.coverage_name`}
                      required={true}
                      variant={inEdition ? 'edit' : undefined}
                      onFocus={() => setFieldTouched(name, true)}
                      onChange={async (__, vocab) => {
                        arrayHelpers.replace(index, { ...value[index], coverage_name: vocab?.toString() });
                      }}
                      disabledOptions={disabledOptions}
                    />
                    <Field
                      component={TextField}
                      variant="outlined"
                      name={`${name}.${index}.coverage_score`}
                      label={t_i18n('Coverage score (0-100)')}
                      type="number"
                      fullWidth
                      min={0}
                      max={100}
                      onChange={(_: string, v: string) => setFieldValue(`${name}.${index}.coverage_score`, parseInt(v, 10))}
                      onFocus={() => setFieldTouched(name, true)}
                      helperText={editContext ? (
                        <SubscriptionFocus
                          context={editContext}
                          fieldName={`${name}.${index}.coverage_score`}
                        />
                      ) : undefined}
                    />
                  </div>
                  <IconButton
                    variant="default"
                    priority="tertiary"
                    disabled={inEdition && value.length < 2}
                    style={{ marginTop: 28 }}
                    id={`deleteCoverageInfo_${index}`}
                    aria-label="Delete"
                    onClick={() => {
                      setFieldTouched(name, true);
                      arrayHelpers.remove(index);
                    }}
                    icon={<DeleteOutlined fontSize="small" />}
                  />
                </div>
              ))}
              <Button
                id="addCoverageInfo"
                variant="secondary"
                aria-label={t_i18n('Add coverage score')}
                onClick={() => {
                  setFieldTouched(name, true);
                  arrayHelpers.push({ coverage_name: null, coverage_score: null });
                }}
              >
                {t_i18n('Add coverage score')}
              </Button>
            </div>
          )}
        />
      </FormGroup>
    </div>
  );
};

export default CoverageInformationField;
