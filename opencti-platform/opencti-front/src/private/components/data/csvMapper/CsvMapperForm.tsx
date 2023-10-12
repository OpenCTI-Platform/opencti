import React, { FunctionComponent, useEffect, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import { TextField } from 'formik-mui';
import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import * as Yup from 'yup';
import { IconButton, Radio, Typography } from '@mui/material';
import { Add } from '@mui/icons-material';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import { FormikHelpers } from 'formik/dist/types';
import { SelectChangeEvent } from '@mui/material/Select';
import CsvMapperRepresentationForm, {
  RepresentationFormEntityOption,
} from '@components/data/csvMapper/representations/CsvMapperRepresentationForm';
import { CsvMapper } from '@components/data/csvMapper/CsvMapper';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import SwitchField from '../../../../components/SwitchField';
import useAuth from '../../../../utils/hooks/useAuth';
import { representationInitialization } from './representations/RepresentationUtils';
import CsvMapperTestDialog from './CsvMapperTestDialog';
import { Representation } from './representations/Representation';

const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  center: {
    display: 'flex',
    alignItems: 'center',
  },
}));

const csvMapperValidation = (t: (s: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  has_header: Yup.boolean().required(t('This field is required')),
  separator: Yup.string().required(t('This field is required')),
});

interface CsvMapperFormProps {
  csvMapper: CsvMapper;
  onSubmit: (values: CsvMapper, formikHelpers: FormikHelpers<CsvMapper>) => void;
}

const CsvMapperForm: FunctionComponent<CsvMapperFormProps> = ({
  csvMapper,
  onSubmit,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();

  // -- INIT --

  // accordion state
  const [open, setOpen] = useState(false);

  // extracting available entities and relationships types from schema
  const { schema } = useAuth();
  const [availableEntityTypes, setAvailableEntityTypes] = useState<RepresentationFormEntityOption[]>([]);
  const [availableRelationshipTypes, setAvailableRelationshipTypes] = useState<RepresentationFormEntityOption[]>([]);

  // load the available types once in state
  useEffect(() => {
    const { sdos, scos, smos, sros } = schema;
    const entityTypes = sdos.map((sdo) => ({ ...sdo, value: sdo.id, type: 'entity_Stix-Domain-Objects' }))
      .concat(scos.map((sco) => ({ ...sco, value: sco.id, type: 'entity_Stix-Cyber-Observables' })))
      .concat(smos.map((smo) => ({ ...smo, value: smo.id, type: 'entity_Stix-Meta-Objects' })));
    const relationshipTypes = sros.map((sro) => ({ ...sro, value: sro.id, type: 'entity_Stix-Core-Relationship' }));

    setAvailableEntityTypes(entityTypes);
    setAvailableRelationshipTypes(relationshipTypes);
  }, [schema]);

  // -- EVENTS --

  const onAddEntityRepresentation = (setFieldValue: (field: string, value: Representation[]) => void, values: CsvMapper) => {
    // we must insert the entity before the relationships as the list is sorted
    const entities = values.representations.filter((r) => r.type === 'entity');
    const relationships = values.representations.filter((r) => r.type === 'relationship');
    setFieldValue('representations', [...entities, representationInitialization('entity'), ...relationships]);
  };
  const onAddRelationshipRepresentation = (setFieldValue: (field: string, value: Representation[]) => void, values: CsvMapper) => {
    // always added at the end
    setFieldValue('representations', [...values.representations, representationInitialization('relationship')]);
  };

  // -- ERRORS --
  const [hasError, setHasError] = useState<boolean>(false);
  let errors: Map<string, string> = new Map();
  const handleRepresentationErrors = (key: string, value: boolean) => {
    errors = { ...errors, [key]: value };
    setHasError(Object.values(errors).filter((v) => v).length > 0);
  };

  return (
    <>
      <Formik<CsvMapper>
        enableReinitialize
        initialValues={csvMapper}
        validationSchema={csvMapperValidation(t)}
        onSubmit={onSubmit}
      >
        {({ submitForm, isSubmitting, setFieldValue, values }) => {
          const entities = values.representations.filter((r) => r.type === 'entity');
          const relationships = values.representations.filter((r) => r.type === 'relationship');

          return (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t('Name')}
                fullWidth
              />
              <div className={classes.center} style={{ marginTop: 20 }}>
                <Field
                  component={SwitchField}
                  type="checkbox"
                  name="has_header"
                  label={t('My csv file contains header')}
                />
                <Tooltip
                  title={t(
                    'If this option is selected, we will skip the first line of your csv file',
                  )}
                >
                  <InformationOutline
                    fontSize="small"
                    color="primary"
                    style={{ cursor: 'default' }}
                  />
                </Tooltip>
              </div>
              <div style={{ marginTop: 20 }}>
                <Typography>
                  {t('Csv separator')}
                </Typography>
                <div className={classes.center}>
                  <Field
                    checked={values.separator !== ';'} // if unset, this is the default option
                    component={Radio}
                    type="radio"
                    name="separator"
                    label="Comma"
                    value=","
                    onChange={(event: SelectChangeEvent) => setFieldValue('separator', event.target.value)}
                  />
                  <Typography>
                    {t('Comma')}
                  </Typography>
                </div>
                <div className={classes.center}>
                  <Field
                    checked={values.separator === ';'}
                    component={Radio}
                    type="radio"
                    name="separator"
                    label="Semicolon"
                    value=";"
                    onChange={(event: SelectChangeEvent) => setFieldValue('separator', event.target.value)}
                  />
                  <Typography>
                    {t('Semicolon')}
                  </Typography>
                </div>
              </div>
              <div className={classes.center} style={{ marginTop: 20 }}>
                <Typography
                  variant="h3"
                  gutterBottom
                  style={{ marginBottom: 0 }}
                >
                  {t('Representations for entity')}
                </Typography>
                <IconButton
                  color="secondary"
                  aria-label="Add"
                  onClick={() => onAddEntityRepresentation(setFieldValue, values)}
                  size="large"
                >
                  <Add fontSize="small"/>
                </IconButton>
              </div>
              {entities.map((representation, idx) => (
                <div
                  key={`entity-${idx}`}
                  style={{ marginTop: 20, display: 'flex' }}
                >
                  <CsvMapperRepresentationForm
                    key={representation.id}
                    index={idx}
                    availableTypes={availableEntityTypes}
                    handleRepresentationErrors={handleRepresentationErrors}
                    prefixLabel='entity_'
                  />
                </div>
              ))}
              <div className={classes.center} style={{ marginTop: 20 }}>
                <Typography
                  variant="h3"
                  gutterBottom
                  style={{ marginBottom: 0 }}
                >
                  {t('Representations for relationship')}
                </Typography>
                <IconButton
                  color="secondary"
                  aria-label="Add"
                  onClick={() => onAddRelationshipRepresentation(setFieldValue, values)}
                  size="large"
                >
                  <Add fontSize="small"/>
                </IconButton>
              </div>
              {relationships.map((representation, idx) => (
                <div
                  key={`relationship-${idx}`}
                  style={{ marginTop: 20, display: 'flex' }}
                >
                  <CsvMapperRepresentationForm
                    key={representation.id}
                    index={entities.length + idx}
                    availableTypes={availableRelationshipTypes}
                    handleRepresentationErrors={handleRepresentationErrors}
                    prefixLabel='relationship_'
                  />
                </div>
              ))}
              <div className={classes.buttons}>
                <Button
                  variant="contained"
                  color="primary"
                  onClick={() => setOpen(true)}
                  classes={{ root: classes.button }}
                  disabled={hasError}
                >
                  {t('Test')}
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={submitForm}
                disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {csvMapper.id ? t('Update') : t('Create')}
                </Button>
              </div>
              <CsvMapperTestDialog
                open={open}
                onClose={() => setOpen(false)}
                configuration={JSON.stringify(values)}
              />
            </Form>
          );
        }
        }
      </Formik>
    </>
  );
};

export default CsvMapperForm;
