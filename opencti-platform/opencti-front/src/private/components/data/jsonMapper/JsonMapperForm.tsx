import React, { FunctionComponent, useEffect, useState } from 'react';
import { Field, FieldArray, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import makeStyles from '@mui/styles/makeStyles';
import * as Yup from 'yup';
import { IconButton, Typography } from '@mui/material';
import { Add } from '@mui/icons-material';
import { FormikHelpers } from 'formik/dist/types';
import JsonMapperRepresentationForm, { RepresentationFormEntityOption } from '@components/data/jsonMapper/representations/JsonMapperRepresentationForm';
import { JsonMapperFormData } from '@components/data/jsonMapper/JsonMapper';
import classNames from 'classnames';
import { JsonMapperProvider } from '@components/data/jsonMapper/JsonMapperContext';
import { formDataToJsonMapper } from '@components/data/jsonMapper/JsonMapperUtils';
import JsonMapperTestDialog from '@components/data/jsonMapper/JsonMapperTestDialog';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import useAuth from '../../../../utils/hooks/useAuth';
import { representationInitialization } from './representations/RepresentationUtils';
import {
  JsonMapperRepresentationAttributesForm_allSchemaAttributes$data,
} from './representations/attributes/__generated__/JsonMapperRepresentationAttributesForm_allSchemaAttributes.graphql';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
  marginTop: {
    marginTop: 20,
  },
  representationContainer: {
    marginTop: 20,
    display: 'flex',
  },
}));

const jsonMapperValidation = (t_i18n: (s: string) => string) => Yup.object().shape({
  name: Yup.string().trim().required(t_i18n('This field is required')),
});

interface JsonMapperFormProps {
  jsonMapper: JsonMapperFormData;
  onSubmit: (
    values: JsonMapperFormData,
    formikHelpers: FormikHelpers<JsonMapperFormData>,
  ) => void;
  isDuplicated?: boolean;
  attributes: JsonMapperRepresentationAttributesForm_allSchemaAttributes$data['csvMapperSchemaAttributes'];
}

const JsonMapperForm: FunctionComponent<JsonMapperFormProps> = ({ jsonMapper, onSubmit, isDuplicated, attributes }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();

  // accordion state
  const [open, setOpen] = useState(false);

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
    setFieldValue: FormikHelpers<JsonMapperFormData>['setFieldValue'],
    values: JsonMapperFormData,
  ) => {
    setFieldValue('entity_representations', [
      ...values.entity_representations,
      representationInitialization('entity'),
    ]);
  };
  const onAddRelationshipRepresentation = (
    setFieldValue: FormikHelpers<JsonMapperFormData>['setFieldValue'],
    values: JsonMapperFormData,
  ) => {
    // always added at the end
    setFieldValue('relationship_representations', [
      ...values.relationship_representations,
      representationInitialization('relationship'),
    ]);
  };

  const getButtonText = () => {
    if (isDuplicated) {
      return t_i18n('Duplicate');
    }
    if (jsonMapper.id) {
      return t_i18n('Update');
    }
    return t_i18n('Create');
  };

  // -- ERRORS --
  // on edit mode, jsonMapper.errors might be set; on create mode backend validation is not done yet so error is null
  const [hasError, setHasError] = useState<boolean>(
    !!jsonMapper.errors?.length
    || (jsonMapper.entity_representations.length === 0 && jsonMapper.relationship_representations.length === 0),
  );
  let errors: Map<string, string> = new Map();
  const handleRepresentationErrors = (key: string, value: boolean) => {
    errors = { ...errors, [key]: value };
    setHasError(Object.values(errors).filter((v) => v).length > 0);
  };
  return (
    <JsonMapperProvider>
      <Formik<JsonMapperFormData>
        enableReinitialize
        initialValues={jsonMapper}
        validationSchema={jsonMapperValidation(t_i18n)}
        onSubmit={onSubmit}
      >
        {({ submitForm, isSubmitting, setFieldValue, values }) => {
          return (
            <Form>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                fullWidth
              />
              <div className={classNames(classes.center, classes.marginTop)}>
                <Typography variant="h3" sx={{ m: 0 }}>
                  {t_i18n('Representations for entity')}
                </Typography>
                <IconButton
                  color="secondary"
                  aria-label="Add"
                  onClick={() => onAddEntityRepresentation(setFieldValue, values)}
                >
                  <Add fontSize="small" />
                </IconButton>
              </div>
              <FieldArray
                name="entity_representations"
                render={(arrayHelpers) => (
                  <>
                    {values.entity_representations.map((_, idx) => (
                      <div
                        key={`entity-${idx}`}
                        className={classes.representationContainer}
                      >
                        <Field
                          component={JsonMapperRepresentationForm}
                          name={`entity_representations[${idx}]`}
                          index={idx}
                          attributes={attributes}
                          availableTypes={availableEntityTypes}
                          handleRepresentationErrors={handleRepresentationErrors}
                          prefixLabel="entity_"
                          onDelete={() => arrayHelpers.remove(idx)}
                        />
                      </div>
                    ))}
                  </>
                )}
              />

              <div className={classNames(classes.center, classes.marginTop)}>
                <Typography variant="h3" sx={{ m: 0 }}>
                  {t_i18n('Representations for relationship')}
                </Typography>
                <IconButton
                  color="secondary"
                  aria-label="Add"
                  onClick={() => onAddRelationshipRepresentation(setFieldValue, values)}
                >
                  <Add fontSize="small" />
                </IconButton>
              </div>
              <FieldArray
                name="relationship_representations"
                render={(arrayHelpers) => (
                  <>
                    {values.relationship_representations.map((_, idx) => (
                      <div
                        key={`relationship-${idx}`}
                        className={classes.representationContainer}
                      >
                        <Field
                          component={JsonMapperRepresentationForm}
                          name={`relationship_representations[${idx}]`}
                          index={idx}
                          attributes={attributes}
                          availableTypes={availableRelationshipTypes}
                          handleRepresentationErrors={handleRepresentationErrors}
                          prefixLabel="relationship_"
                          onDelete={() => arrayHelpers.remove(idx)}
                        />
                      </div>
                    ))}
                  </>
                )}
              />

              <div className={classes.buttons}>
                <Button
                  color="primary"
                  onClick={() => setOpen(true)}
                  classes={{ root: classes.button }}
                  disabled={hasError}
                >
                  {t_i18n('Test')}
                </Button>
                <Button
                  color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {getButtonText()}
                </Button>
              </div>
              <JsonMapperTestDialog
                open={open}
                onClose={() => setOpen(false)}
                configuration={JSON.stringify(formDataToJsonMapper(values))}
              />
            </Form>
          );
        }}
      </Formik>
    </JsonMapperProvider>
  );
};

export default JsonMapperForm;
