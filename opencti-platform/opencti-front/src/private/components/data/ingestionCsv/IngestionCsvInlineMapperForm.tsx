import React, { FunctionComponent, useEffect, useState } from 'react';
import { Field, FieldArray, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { IconButton, Radio, RadioGroup, Typography } from '@mui/material';
import { Add } from '@mui/icons-material';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import { FormikHelpers } from 'formik/dist/types';
import { SelectChangeEvent } from '@mui/material/Select';
import CsvMapperRepresentationForm, { RepresentationFormEntityOption } from '@components/data/csvMapper/representations/CsvMapperRepresentationForm';
import { CsvMapperFormData } from '@components/data/csvMapper/CsvMapper';
import FormControlLabel from '@mui/material/FormControlLabel';
import { CsvMapperProvider } from '@components/data/csvMapper/CsvMapperContext';
import Box from '@mui/material/Box';
import { csvFeedCsvMapperToFormData } from '@components/data/ingestionCsv/IngestionCSVFeedUtils';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import SwitchField from '../../../../components/fields/SwitchField';
import useAuth from '../../../../utils/hooks/useAuth';
import { representationInitialization } from '../csvMapper/representations/RepresentationUtils';
import { CsvMapperAddInput, formDataToCsvMapper } from '../csvMapper/CsvMapperUtils';

const csvMapperValidation = (t_i18n: (s: string) => string) => Yup.object().shape({
  has_header: Yup.boolean().required(t_i18n('This field is required')),
  separator: Yup.string().trim().required(t_i18n('This field is required')),
  skipLineChar: Yup.string().max(1),
});

const defaultCsvMapperValue: CsvMapperFormData = {
  id: '',
  name: '',
  has_header: false,
  separator: ',',
  skip_line_char: '',
  entity_representations: [],
  relationship_representations: [],
};

interface CsvMapperFormProps {
  csvMapper?: CsvMapperAddInput;
  setCSVMapperFieldValue: (field: string, value: CsvMapperAddInput) => void;
  returnCSVFormat?: (field: string, value: CsvMapperAddInput) => void;
}

const IngestionCsvInlineMapperForm: FunctionComponent<CsvMapperFormProps> = ({ csvMapper, setCSVMapperFieldValue, returnCSVFormat }) => {
  const csvMapperFormData = csvMapper ? csvFeedCsvMapperToFormData(csvMapper) : defaultCsvMapperValue;
  const { t_i18n } = useFormatter();
  // extracting available entities and relationships types from schema
  const { schema } = useAuth();
  const [availableEntityTypes, setAvailableEntityTypes] = useState<
    RepresentationFormEntityOption[]
  >([]);
  const [availableRelationshipTypes, setAvailableRelationshipTypes] = useState<
    RepresentationFormEntityOption[]
  >([]);

  // load the available types once in state
  useEffect(() => {
    const { sdos, scos, smos, scrs } = schema;
    const entityTypes = sdos
      .map((sdo) => ({
        ...sdo,
        value: sdo.id,
        type: 'entity_Stix-Domain-Objects',
      }))
      .concat(
        scos.map((sco) => ({
          ...sco,
          value: sco.id,
          type: 'entity_Stix-Cyber-Observables',
        })),
      )
      .concat(
        smos.map((smo) => ({
          ...smo,
          value: smo.id,
          type: 'entity_Stix-Meta-Objects',
        })),
      );
    const relationshipTypes = scrs
      .map((scr) => ({
        ...scr,
        value: scr.id,
        type: 'entity_Stix-Core-Relationship',
      })).concat({
        id: 'stix-sighting-relationship',
        label: 'stix-sighting-relationship',
        value: 'stix-sighting-relationship',
        type: 'entity_stix-sighting-relationship',
      });

    setAvailableEntityTypes(entityTypes);
    setAvailableRelationshipTypes(relationshipTypes);
  }, [schema]);

  // -- EVENTS --

  const onAddEntityRepresentation = (
    setFieldValue: FormikHelpers<CsvMapperFormData>['setFieldValue'],
    values: CsvMapperFormData,
  ) => {
    setFieldValue('entity_representations', [
      ...values.entity_representations,
      representationInitialization('entity'),
    ]);
  };
  const onAddRelationshipRepresentation = (
    setFieldValue: FormikHelpers<CsvMapperFormData>['setFieldValue'],
    values: CsvMapperFormData,
  ) => {
    // always added at the end
    setFieldValue('relationship_representations', [
      ...values.relationship_representations,
      representationInitialization('relationship'),
    ]);
  };

  // -- ERRORS --
  // on edit mode, csvMapperFormData.errors might be set; on create mode backend validation is not done yet so error is null
  const [hasError, setHasError] = useState<boolean>(
    !!csvMapperFormData.errors?.length
    || (csvMapperFormData.entity_representations.length === 0 && csvMapperFormData.relationship_representations.length === 0),
  );
  let errors: Map<string, string> = new Map();
  const handleRepresentationErrors = (key: string, value: boolean) => {
    errors = { ...errors, [key]: value };
    setHasError(Object.values(errors).filter((v) => v).length > 0);
  };

  useEffect(() => {
    if (returnCSVFormat) {
      returnCSVFormat('csv_mapper', formDataToCsvMapper(csvMapperFormData) as unknown as CsvMapperAddInput);
    }
  }, []);

  const handleOnSubmit = (values: CsvMapperFormData) => {
    setCSVMapperFieldValue('csv_mapper', formDataToCsvMapper(values) as unknown as CsvMapperAddInput);
  };
  return (
    <CsvMapperProvider>
      <Formik<CsvMapperFormData>
        enableReinitialize
        initialValues={csvMapperFormData}
        validationSchema={csvMapperValidation(t_i18n)}
        onSubmit={handleOnSubmit}
      >
        {({ setFieldValue, values, dirty }) => {
          useEffect(() => {
            if (dirty && !hasError) {
              setCSVMapperFieldValue('csv_mapper', formDataToCsvMapper(values) as unknown as CsvMapperAddInput);
            }
          }, [values, dirty, hasError]);
          return (
            <Form>
              <Box sx={{
                display: 'flex',
                alignItems: 'center',
                marginTop: 2.5,
              }}
              >
                <Field
                  component={SwitchField}
                  type="checkbox"
                  name="has_header"
                  label={t_i18n('My CSV file contains headers')}
                />
                <Tooltip
                  title={t_i18n(
                    'If this option is selected, we will skip the first line of your CSV file',
                  )}
                >
                  <InformationOutline
                    fontSize="small"
                    color="primary"
                    style={{ cursor: 'default' }}
                  />
                </Tooltip>
              </Box>
              <Box sx={{
                marginTop: 2.5,
              }}
              >
                <Typography>{t_i18n('CSV separator')}</Typography>
                <Box sx={{
                  display: 'flex',
                  alignItems: 'center',
                }}
                >
                  <RadioGroup
                    aria-label="CSV separator"
                    name="separator"
                    style={{ flexDirection: 'row' }}
                    value={values.separator}
                    onChange={(event: SelectChangeEvent) => setFieldValue('separator', event.target.value)}
                  >
                    <FormControlLabel
                      value=","
                      control={<Radio />}
                      label={t_i18n('Comma')}
                    />
                    <FormControlLabel
                      value=";"
                      control={<Radio />}
                      label={t_i18n('Semicolon')}
                    />
                    <FormControlLabel
                      value="|"
                      control={<Radio />}
                      label={t_i18n('Pipe')}
                    />
                  </RadioGroup>
                </Box>
              </Box>
              <Box
                sx={{
                  marginTop: 2.5,
                  display: 'flex',
                  alignItems: 'end',
                  gap: '8px',

                }}
              >
                <Field
                  component={TextField}
                  name="skip_line_char"
                  label={t_i18n('Char to escape line')}
                />
                <Tooltip
                  title={t_i18n(
                    'Every line that begins with this character will be skipped during parsing (for example: #).',
                  )}
                >
                  <InformationOutline
                    fontSize="small"
                    color="primary"
                    style={{ cursor: 'default' }}
                  />
                </Tooltip>
              </Box>

              <Box sx={{
                display: 'flex',
                alignItems: 'center',
                marginTop: 2.5,
              }}
              >
                <Typography variant="h3" sx={{ m: 0 }}>
                  {t_i18n('Representations for entity')}
                </Typography>
                <IconButton
                  color="secondary"
                  aria-label="Add"
                  onClick={() => onAddEntityRepresentation(setFieldValue, values)
                  }
                >
                  <Add fontSize="small" />
                </IconButton>
              </Box>
              <FieldArray
                name="entity_representations"
                render={(arrayHelpers) => (
                  <>
                    {values.entity_representations.map((_, idx) => (
                      <Box
                        key={`entity-${idx}`}
                        sx={{
                          marginTop: 2.5,
                          display: 'flex',
                        }}
                      >
                        <Field
                          component={CsvMapperRepresentationForm}
                          name={`entity_representations[${idx}]`}
                          index={idx}
                          availableTypes={availableEntityTypes}
                          handleRepresentationErrors={handleRepresentationErrors}
                          prefixLabel="entity_"
                          onDelete={() => arrayHelpers.remove(idx)}
                        />
                      </Box>
                    ))}
                  </>
                )}
              />

              <Box sx={{
                display: 'flex',
                alignItems: 'center',
                marginTop: 2.5,
              }}
              >
                <Typography variant="h3" sx={{ m: 0 }}>
                  {t_i18n('Representations for relationship')}
                </Typography>
                <IconButton
                  color="secondary"
                  aria-label="Add"
                  onClick={() => onAddRelationshipRepresentation(setFieldValue, values)
                  }
                >
                  <Add fontSize="small" />
                </IconButton>
              </Box>
              <FieldArray
                name="relationship_representations"
                render={(arrayHelpers) => (
                  <>
                    {values.relationship_representations.map((_, idx) => (
                      <Box
                        sx={{
                          marginTop: 2.5,
                          display: 'flex',
                        }}
                        key={`relationship-${idx}`}
                      >
                        <Field
                          component={CsvMapperRepresentationForm}
                          name={`relationship_representations[${idx}]`}
                          index={idx}
                          availableTypes={availableRelationshipTypes}
                          handleRepresentationErrors={handleRepresentationErrors}
                          prefixLabel="relationship_"
                          onDelete={() => arrayHelpers.remove(idx)}
                        />
                      </Box>
                    ))}
                  </>
                )}
              />
            </Form>
          );
        }}
      </Formik>
    </CsvMapperProvider>
  );
};

export default IngestionCsvInlineMapperForm;
