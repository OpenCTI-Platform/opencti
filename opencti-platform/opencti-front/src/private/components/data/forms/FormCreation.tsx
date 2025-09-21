import React, { FunctionComponent, Suspense, useMemo, useState } from 'react';
import { Field, FieldArray, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { Add, DeleteOutlined } from '@mui/icons-material';
import { FormikHelpers } from 'formik/dist/types';
import { FormLinesPaginationQuery$variables } from '@components/data/forms/__generated__/FormLinesPaginationQuery.graphql';
import { Box, IconButton, MenuItem, Tab, Tabs, Typography } from '@mui/material';
import { FormCreationQuery } from '@components/data/forms/__generated__/FormCreationQuery.graphql';
import Drawer from '../../common/drawer/Drawer';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, handleError } from '../../../../relay/environment';
import SwitchField from '../../../../components/fields/SwitchField';
import { insertNode } from '../../../../utils/store';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import type { Theme } from '../../../../components/Theme';
import SelectField from '../../../../components/fields/SelectField';
import useAuth from '../../../../utils/hooks/useAuth';
import {
  buildEntityTypes,
  CONTAINER_TYPES,
  FIELD_TYPES,
  generateEntityId,
  generateFieldId,
  generateRelationshipId,
  getAttributesForEntityType as getAttributesUtil,
  getInitialMandatoryFields,
} from './FormUtils';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';

const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  tabContent: {
    paddingTop: 20,
  },
  entitySection: {
    marginBottom: 20,
  },
  entityHeader: {
    backgroundColor: theme.palette.background.default,
    padding: 15,
    borderRadius: 4,
    marginBottom: 10,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  fieldGroup: {
    marginTop: 10,
    padding: 15,
    borderRadius: 4,
    border: `1px solid ${theme.palette.divider}`,
    position: 'relative',
  },
  fieldHeader: {
    display: 'flex',
    alignItems: 'center',
    marginBottom: 10,
  },
  fieldTitle: {
    flex: 1,
    fontWeight: 500,
  },
  addFieldButton: {
    marginTop: 10,
    width: '100%',
    borderStyle: 'dashed',
  },
  addEntityButton: {
    marginTop: 20,
    width: '100%',
  },
  relationshipGroup: {
    marginTop: 10,
    padding: 15,
    borderRadius: 4,
    border: `1px solid ${theme.palette.divider}`,
  },
}));

const formCreationMutation = graphql`
  mutation FormCreationMutation($input: FormAddInput!) {
    formAdd(input: $input) {
      id
      name
      description
      form_schema
      active
      created_at
      updated_at
    }
  }
`;

// Constants are imported from FormUtils

interface FormFieldAttribute {
  id: string;
  name: string;
  description?: string;
  type: string; // Field type: text, select, etc.
  required: boolean;
  isMandatory?: boolean; // Whether this field is for a mandatory attribute
  attributeMapping: {
    entity: string; // Entity ID this field maps to (main_entity or additional entity ID)
    attribute: string; // The attribute name on that entity
  };
  fieldMode?: 'single' | 'parsed' | 'multi'; // For fields in multiple entities
  parseMode?: 'comma' | 'line'; // For text/textarea with fieldMode='parsed'
}

interface AdditionalEntity {
  id: string;
  type: string; // Entity type
  name: string; // Display name for this entity in the form
  multiple: boolean; // Whether this entity allows multiple instances
  entityLookup?: boolean; // Whether to use entity lookup for this entity
}

interface EntityRelationship {
  id: string;
  from: string; // Entity ID (main_entity or additional entity ID)
  to: string; // Entity ID (main_entity or additional entity ID)
  type: string; // Relationship type
}

interface FormBuilderData {
  name: string;
  description?: string;
  mainEntityType: string;
  mainEntityMultiple: boolean; // Whether main entity allows multiple
  mainEntityLookup?: boolean; // Whether to use entity lookup for main entity
  additionalEntities: AdditionalEntity[];
  fields: FormFieldAttribute[];
  relationships: EntityRelationship[];
  active: boolean;
}

interface FormAddInput {
  name: string;
  description?: string;
  form_schema: string;
  active?: boolean;
}

interface FormCreationProps {
  queryRef: PreloadedQuery<FormCreationQuery>
  handleClose: () => void;
  paginationOptions: FormLinesPaginationQuery$variables;
}

export const formCreationQuery = graphql`
  query FormCreationQuery {
    entitySettings {
      edges {
        node {
          id
          target_type
          platform_entity_files_ref
          platform_hidden_type
          enforce_reference
          availableSettings
          mandatoryAttributes
          attributesDefinitions {
            type
            name
            label
            mandatory
            mandatoryType
            multiple
            scale
            defaultValues {
              id
              name
            }
          }
        }
      }
    }
  }
`;

const FormCreation: FunctionComponent<FormCreationProps> = ({
  queryRef,
  handleClose,
  paginationOptions,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { schema } = useAuth();
  const [currentTab, setCurrentTab] = useState(0);

  const { entitySettings } = usePreloadedQuery(formCreationQuery, queryRef);
  if (!entitySettings) {
    return <ErrorNotFound />;
  }

  // Get available entity types from schema using buildEntityTypes from FormUtils
  const entityTypes = useMemo(() => {
    if (!schema || !entitySettings) {
      return [];
    }
    return buildEntityTypes(schema, entitySettings, t_i18n);
  }, [schema, entitySettings, t_i18n]);

  // Get attributes for a specific entity type that match field type
  const getAttributesForEntityType = (entityType: string, fieldType: string) => {
    return getAttributesUtil(entityType, fieldType, entityTypes, t_i18n);
  };

  // Get relationship types available for specific entity combinations
  const getAvailableRelationships = (fromType: string, toType: string) => {
    if (!fromType || !toType) return [];

    const { scrs, schemaRelationsTypesMapping } = schema;
    const allRelationshipTypes = scrs.map((s) => ({
      value: s.id,
      label: t_i18n(`relationship_${s.id}`),
    }));

    // Get mappings for both entity types
    const fromMappings = schemaRelationsTypesMapping?.get(fromType) || [];
    const toMappings = schemaRelationsTypesMapping?.get(toType) || [];

    // Only return relationships that are valid for BOTH entity types
    const validRelationships = allRelationshipTypes.filter((rel) => {
      // A relationship is valid if it's in the mapping for either entity
      // (relationships are bidirectional)
      return fromMappings.includes(rel.value) || toMappings.includes(rel.value);
    });

    // If no specific mappings found, return empty (more restrictive)
    return validRelationships.length > 0 ? validRelationships : [];
  };

  const formValidation = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    mainEntityType: Yup.string().required(t_i18n('This field is required')),
    additionalEntities: Yup.array(),
    fields: Yup.array().of(
      Yup.object().shape({
        id: Yup.string().required(),
        name: Yup.string().required(t_i18n('This field is required')),
        type: Yup.string().required(t_i18n('This field is required')),
        attributeMapping: Yup.object().shape({
          entity: Yup.string().required(),
          attribute: Yup.string().required(t_i18n('This field is required')),
        }),
      }),
    ),
    relationships: Yup.array(),
    active: Yup.boolean(),
  });

  const onSubmit = (
    values: FormBuilderData,
    { setSubmitting, resetForm }: FormikHelpers<FormBuilderData>,
  ) => {
    // Check if main entity is a container
    const isMainEntityContainer = CONTAINER_TYPES.includes(values.mainEntityType);

    // Convert the new form structure to the schema format expected by backend
    const formSchema = {
      version: '2.0',
      mainEntityType: values.mainEntityType,
      isContainer: isMainEntityContainer,
      additionalEntities: values.additionalEntities,
      fields: values.fields.map((field) => ({
        id: field.id,
        name: field.name,
        description: field.description,
        type: field.type,
        required: field.required,
        parseMode: field.parseMode,
        // Map attribute to stixPath based on entity
        stixPath: field.attributeMapping.entity === 'main_entity'
          ? field.attributeMapping.attribute
          : undefined,
        // If mapping to additional entity, store entity and attribute info
        entityMapping: field.attributeMapping.entity !== 'main_entity'
          ? {
            entityId: field.attributeMapping.entity,
            attribute: field.attributeMapping.attribute,
          }
          : undefined,
      })),
      relationships: values.relationships,
    };

    const input: FormAddInput = {
      name: values.name,
      description: values.description,
      form_schema: JSON.stringify(formSchema),
      active: values.active,
    };

    commitMutation({
      mutation: formCreationMutation,
      variables: { input },
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      setSubmitting,
      updater: (store: any) => {
        insertNode(
          store,
          'Pagination_forms',
          paginationOptions,
          'formAdd',
        );
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
      },
      onError: (error: any) => {
        handleError(error);
        setSubmitting(false);
      },
    });
  };

  // ID generation functions are imported from FormUtils

  // Get initial mandatory fields for default entity type
  // ID generation functions are imported from FormUtils

  const initialValues: FormBuilderData = useMemo(() => {
    // Pre-populate mandatory fields for default entity type (Report)
    const defaultEntityType = 'Report';
    const defaultMandatoryFields = entityTypes.length > 0
      ? getInitialMandatoryFields(defaultEntityType, entityTypes, t_i18n)
      : [];

    return {
      name: '',
      description: '',
      mainEntityType: defaultEntityType,
      mainEntityMultiple: false,
      mainEntityLookup: false,
      additionalEntities: [],
      fields: defaultMandatoryFields,
      relationships: [],
      active: true,
    };
  }, [entityTypes, t_i18n]);

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={formValidation}
      onSubmit={onSubmit}
    >
      {({ submitForm, handleReset, isSubmitting, values, setFieldValue }) => {
        const mainEntityInfo = entityTypes.find((e) => e.value === values.mainEntityType);
        const isContainer = mainEntityInfo?.isContainer || false;

        // Group fields by entity
        const fieldsByEntity = values.fields.reduce((acc, field) => {
          const entityId = field.attributeMapping.entity;
          if (!acc[entityId]) {
            acc[entityId] = [];
          }
          acc[entityId].push(field);
          return acc;
        }, {} as Record<string, FormFieldAttribute[]>);

        return (
          <Form>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              fullWidth={true}
              detectDuplicate={['Form']}
            />
            <Field
              component={TextField}
              variant="standard"
              name="description"
              label={t_i18n('Description')}
              fullWidth={true}
              multiline={true}
              rows={3}
              style={{ marginTop: 20 }}
            />
            <Field
              component={SelectField}
              variant="standard"
              name="mainEntityType"
              label={t_i18n('Main Entity Type')}
              helpertext={isContainer ? t_i18n('This is a container entity. All entities and relationships will be automatically added to the container.') : undefined}
              fullWidth={true}
              containerstyle={{ width: '100%', marginTop: 20 }}
              onChange={(_: never, value: any) => {
                // Reset main entity fields when entity type changes
                const nonMainFields = values.fields.filter((f: any) => f.attributeMapping?.entity !== 'main_entity');

                // Pre-populate mandatory fields for this entity type
                const newMandatoryFields = getInitialMandatoryFields(value, entityTypes, t_i18n);
                setFieldValue('fields', [...nonMainFields, ...newMandatoryFields]);
              }}
            >
              {entityTypes.map((type) => (
                <MenuItem key={type.value} value={type.value}>
                  {type.label}
                  {type.isContainer && ` (${t_i18n('Container')})`}
                </MenuItem>
              ))}
            </Field>

            <Field
              component={SwitchField}
              type="checkbox"
              name="mainEntityMultiple"
              label={t_i18n('Allow multiple instances of main entity')}
              containerstyle={{ marginTop: 20 }}
            />

            <Field
              component={SwitchField}
              type="checkbox"
              name="mainEntityLookup"
              label={t_i18n('Entity lookup (select existing entities)')}
              containerstyle={{ marginTop: 20 }}
            />

            <Field
              component={SwitchField}
              type="checkbox"
              name="active"
              label={t_i18n('Active')}
              containerstyle={{ marginTop: 20 }}
            />

            <Box sx={{ borderBottom: 1, borderColor: 'divider', marginTop: 3 }}>
              <Tabs value={currentTab} onChange={(e, v) => setCurrentTab(v)}>
                <Tab label={t_i18n('Entities')} />
                <Tab label={t_i18n('Relationships')} />
              </Tabs>
            </Box>

            {currentTab === 0 && (
              <div className={classes.tabContent}>
                {/* Main Entity Section */}
                <div className={classes.entitySection}>
                  <div className={classes.entityHeader}>
                    <Typography variant="h6">
                      {t_i18n('Main Entity')}: {mainEntityInfo?.label}
                    </Typography>
                  </div>

                  {values.mainEntityLookup ? (
                    <Typography variant="body2" style={{ padding: 20, fontStyle: 'italic' }}>
                      {t_i18n('Entity lookup enabled. Users will select existing entities of this type.')}
                    </Typography>
                  ) : (
                    <FieldArray name="fields">
                      {({ push }) => (
                        <>
                          {fieldsByEntity.main_entity?.map((field) => {
                            const fieldIndex = values.fields.findIndex((f) => f.id === field.id);
                            return (
                              <div key={field.id} className={classes.fieldGroup}>
                                <div className={classes.fieldHeader}>
                                  <Typography className={classes.fieldTitle}>
                                    {field.name || t_i18n('Field')}
                                  </Typography>
                                  <IconButton
                                    size="small"
                                    color="primary"
                                    disabled={field.isMandatory} // Disable delete for mandatory fields
                                    onClick={() => {
                                      const idx = values.fields.findIndex((f) => f.id === field.id);
                                      if (idx !== -1) {
                                        const newFields = [...values.fields];
                                        newFields.splice(idx, 1);
                                        setFieldValue('fields', newFields);
                                      }
                                    }}
                                  >
                                    <DeleteOutlined />
                                  </IconButton>
                                </div>

                                <Field
                                  component={TextField}
                                  variant="standard"
                                  name={`fields.${fieldIndex}.name`}
                                  label={t_i18n('Field Name')}
                                  fullWidth={true}
                                />
                                <Field
                                  component={TextField}
                                  variant="standard"
                                  name={`fields.${fieldIndex}.description`}
                                  label={t_i18n('Field Description')}
                                  fullWidth={true}
                                  style={{ marginTop: 20 }}
                                />
                                <Field
                                  component={SelectField}
                                  variant="standard"
                                  name={`fields.${fieldIndex}.type`}
                                  label={t_i18n('Field Type')}
                                  fullWidth={true}
                                  containerstyle={{ width: '100%', marginTop: 20 }}
                                  onChange={(_: any, value: any) => {
                                    setFieldValue(`fields.${fieldIndex}.type`, value);
                                    // Reset attribute mapping when type changes
                                    setFieldValue(`fields.${fieldIndex}.attributeMapping.attribute`, '');
                                    // Reset multiple and parseMode
                                    setFieldValue(`fields.${fieldIndex}.multiple`, false);
                                    setFieldValue(`fields.${fieldIndex}.parseMode`, undefined);
                                  }}
                                >
                                  {FIELD_TYPES.map((type) => (
                                    <MenuItem key={type.value} value={type.value}>
                                      {type.label}
                                    </MenuItem>
                                  ))}
                                </Field>

                                {/* Attribute mapping */}
                                <Field
                                  component={SelectField}
                                  variant="standard"
                                  name={`fields.${fieldIndex}.attributeMapping.attribute`}
                                  label={t_i18n('Map to Attribute')}
                                  fullWidth={true}
                                  containerstyle={{ width: '100%', marginTop: 20 }}
                                >
                                  <MenuItem value="">
                                    {t_i18n('Select an attribute')}
                                  </MenuItem>
                                  {getAttributesForEntityType(values.mainEntityType, field.type).map((attr: any) => (
                                    <MenuItem key={attr.value} value={attr.value}>
                                      {attr.label}
                                    </MenuItem>
                                  ))}
                                </Field>

                                {/* Field mode for entities with multiple support */}
                                {values.mainEntityMultiple && (field.type === 'text' || field.type === 'textarea') && (
                                <Field
                                  component={SelectField}
                                  variant="standard"
                                  name={`fields.${fieldIndex}.fieldMode`}
                                  label={t_i18n('Field Mode')}
                                  fullWidth={true}
                                  containerstyle={{ width: '100%', marginTop: 20 }}
                                  value={field.fieldMode || 'multi'}
                                  onChange={(e: any, value: any) => {
                                    setFieldValue(`fields.${fieldIndex}.fieldMode`, value);
                                    // If switching to parsed mode, set default parse mode
                                    if (value === 'parsed' && !field.parseMode) {
                                      setFieldValue(`fields.${fieldIndex}.parseMode`, 'comma');
                                    }
                                  }}
                                >
                                  <MenuItem value="multi">{t_i18n('Multiple fields (+ button)')}</MenuItem>
                                  {(field.type === 'text' || field.type === 'textarea') && (
                                    <MenuItem value="parsed">{t_i18n('Parsed values')}</MenuItem>
                                  )}
                                </Field>
                                )}

                                <Field
                                  component={SwitchField}
                                  type="checkbox"
                                  name={`fields.${fieldIndex}.required`}
                                  label={t_i18n('Required')}
                                  disabled={field.isMandatory} // Disable for mandatory fields
                                  containerstyle={{ marginTop: 20 }}
                                />

                                {/* Parse mode only for parsed text/textarea */}
                                {field.fieldMode === 'parsed' && (field.type === 'text' || field.type === 'textarea') && (
                                <Field
                                  component={SelectField}
                                  variant="standard"
                                  name={`fields.${fieldIndex}.parseMode`}
                                  label={t_i18n('Parse mode')}
                                  fullWidth={true}
                                  containerstyle={{ width: '100%', marginTop: 20 }}
                                  value={field.parseMode || 'comma'}
                                >
                                  <MenuItem value="comma">{t_i18n('Comma-separated')}</MenuItem>
                                  {field.type === 'textarea' && (
                                    <MenuItem value="line">{t_i18n('One per line')}</MenuItem>
                                  )}
                                </Field>
                                )}
                              </div>
                            );
                          })}

                          <Button
                            variant="contained"
                            color="primary"
                            startIcon={<Add />}
                            className={classes.addFieldButton}
                            onClick={() => {
                              const newField: FormFieldAttribute = {
                                id: generateFieldId(),
                                name: '',
                                type: 'text',
                                required: false,
                                attributeMapping: {
                                  entity: 'main_entity',
                                  attribute: '',
                                },
                                ...(values.mainEntityMultiple ? { fieldMode: 'multi' } : {}),
                              };
                              push(newField);
                            }}
                          >
                            {t_i18n('Add Field to Main Entity')}
                          </Button>
                        </>
                      )}
                    </FieldArray>
                  )}
                </div>

                {/* Additional Entities */}
                <FieldArray name="additionalEntities">
                  {({ push: pushEntity, remove: removeEntity }) => (
                    <>
                      {values.additionalEntities.map((entity, entityIndex) => {
                        const entityFields = fieldsByEntity[entity.id] || [];
                        return (
                          <div key={entity.id} className={classes.entitySection}>
                            <div className={classes.entityHeader}>
                              <Box>
                                <Field
                                  component={TextField}
                                  variant="standard"
                                  name={`additionalEntities.${entityIndex}.name`}
                                  label={t_i18n('Label for entities')}
                                  style={{ marginRight: 20, minWidth: 200 }}
                                />
                                <Field
                                  component={SelectField}
                                  variant="standard"
                                  name={`additionalEntities.${entityIndex}.type`}
                                  label={t_i18n('Entity Type')}
                                  style={{ minWidth: 200, marginRight: 20 }}
                                >
                                  {entityTypes.map((type) => (
                                    <MenuItem key={type.value} value={type.value}>
                                      {type.label}
                                    </MenuItem>
                                  ))}
                                </Field>
                                <Field
                                  component={SwitchField}
                                  type="checkbox"
                                  name={`additionalEntities.${entityIndex}.multiple`}
                                  label={t_i18n('Multiple')}
                                  containerstyle={{ marginTop: 0 }}
                                />
                                <Field
                                  component={SwitchField}
                                  type="checkbox"
                                  name={`additionalEntities.${entityIndex}.entityLookup`}
                                  label={t_i18n('Entity lookup')}
                                  containerstyle={{ marginTop: 0, marginLeft: 20 }}
                                />
                              </Box>
                              <IconButton
                                color="primary"
                                onClick={() => {
                                  // Remove entity
                                  removeEntity(entityIndex);
                                  // Remove all fields associated with this entity
                                  const newFields = values.fields.filter(
                                    (f) => f.attributeMapping.entity !== entity.id,
                                  );
                                  setFieldValue('fields', newFields);
                                  // Remove relationships involving this entity
                                  const newRelationships = values.relationships.filter(
                                    (r) => r.from !== entity.id && r.to !== entity.id,
                                  );
                                  setFieldValue('relationships', newRelationships);
                                }}
                              >
                                <DeleteOutlined />
                              </IconButton>
                            </div>

                            {entity.entityLookup ? (
                              <Typography variant="body2" style={{ padding: 20, fontStyle: 'italic' }}>
                                {t_i18n('Entity lookup enabled. Users will select existing entities of this type.')}
                              </Typography>
                            ) : (
                              <FieldArray name="fields">
                                {({ push: pushField }) => (
                                  <>
                                    {entityFields.map((field) => {
                                      const fieldIndex = values.fields.findIndex((f) => f.id === field.id);
                                      return (
                                        <div key={field.id} className={classes.fieldGroup}>
                                          <div className={classes.fieldHeader}>
                                            <Typography className={classes.fieldTitle}>
                                              {field.name || t_i18n('Field')}
                                            </Typography>
                                            <IconButton
                                              size="small"
                                              color="primary"
                                              disabled={field.isMandatory} // Disable delete for mandatory fields
                                              onClick={() => {
                                                const idx = values.fields.findIndex((f) => f.id === field.id);
                                                if (idx !== -1) {
                                                  const newFields = [...values.fields];
                                                  newFields.splice(idx, 1);
                                                  setFieldValue('fields', newFields);
                                                }
                                              }}
                                            >
                                              <DeleteOutlined />
                                            </IconButton>
                                          </div>

                                          <Field
                                            component={TextField}
                                            variant="standard"
                                            name={`fields.${fieldIndex}.name`}
                                            label={t_i18n('Field Name')}
                                            fullWidth={true}
                                          />
                                          <Field
                                            component={TextField}
                                            variant="standard"
                                            name={`fields.${fieldIndex}.description`}
                                            label={t_i18n('Field Description')}
                                            fullWidth={true}
                                            style={{ marginTop: 20 }}
                                          />
                                          <Field
                                            name={`fields.${fieldIndex}.type`}
                                          >
                                            {({ field: fieldProps, form }: any) => (
                                              <SelectField
                                                {...fieldProps}
                                                form={form}
                                                variant="standard"
                                                label={t_i18n('Field Type')}
                                                fullWidth={true}
                                                containerstyle={{ width: '100%', marginTop: 20 }}
                                                disabled={field.isMandatory} // Disable for mandatory fields
                                                onChange={(_: any, value: any) => {
                                                  setFieldValue(`fields.${fieldIndex}.type`, value);
                                                  // Reset attribute mapping when type changes
                                                  setFieldValue(`fields.${fieldIndex}.attributeMapping.attribute`, '');
                                                  // Reset multiple and parseMode
                                                  setFieldValue(`fields.${fieldIndex}.multiple`, false);
                                                  setFieldValue(`fields.${fieldIndex}.parseMode`, undefined);
                                                }}
                                              >
                                                {FIELD_TYPES.map((type) => (
                                                  <MenuItem key={type.value} value={type.value}>
                                                    {type.label}
                                                  </MenuItem>
                                                ))}
                                              </SelectField>
                                            )}
                                          </Field>

                                          {/* Attribute mapping */}
                                          <Field
                                            name={`fields.${fieldIndex}.attributeMapping.attribute`}
                                          >
                                            {({ field: fieldProps, form }: any) => (
                                              <SelectField
                                                {...fieldProps}
                                                form={form}
                                                variant="standard"
                                                label={t_i18n('Map to Attribute')}
                                                fullWidth={true}
                                                containerstyle={{ width: '100%', marginTop: 20 }}
                                                disabled={field.isMandatory} // Disable for mandatory fields
                                              >
                                                <MenuItem value="">
                                                  {t_i18n('Select an attribute')}
                                                </MenuItem>
                                                {getAttributesForEntityType(entity.type, field.type).map((attr: any) => (
                                                  <MenuItem key={attr.value} value={attr.value}>
                                                    {attr.label}
                                                  </MenuItem>
                                                ))}
                                              </SelectField>
                                            )}
                                          </Field>

                                          {/* Field mode for entities with multiple support */}
                                          {entity.multiple && (field.type === 'text' || field.type === 'textarea') && (
                                          <Field
                                            component={SelectField}
                                            variant="standard"
                                            name={`fields.${fieldIndex}.fieldMode`}
                                            label={t_i18n('Field Mode')}
                                            fullWidth={true}
                                            containerstyle={{ width: '100%', marginTop: 20 }}
                                            value={field.fieldMode || 'multi'}
                                            onChange={(e: any, value: any) => {
                                              setFieldValue(`fields.${fieldIndex}.fieldMode`, value);
                                              // If switching to parsed mode, set default parse mode
                                              if (value === 'parsed' && !field.parseMode) {
                                                setFieldValue(`fields.${fieldIndex}.parseMode`, 'comma');
                                              }
                                            }}
                                          >
                                            <MenuItem value="multi">{t_i18n('Multiple fields (+ button)')}</MenuItem>
                                            {(field.type === 'text' || field.type === 'textarea') && (
                                              <MenuItem value="parsed">{t_i18n('Parsed values')}</MenuItem>
                                            )}
                                          </Field>
                                          )}

                                          <Field
                                            component={SwitchField}
                                            type="checkbox"
                                            name={`fields.${fieldIndex}.required`}
                                            label={t_i18n('Required')}
                                            disabled={field.isMandatory} // Disable for mandatory fields
                                            containerstyle={{ marginTop: 20 }}
                                          />

                                          {/* Parse mode only for parsed text/textarea */}
                                          {field.fieldMode === 'parsed' && (field.type === 'text' || field.type === 'textarea') && (
                                          <Field
                                            component={SelectField}
                                            variant="standard"
                                            name={`fields.${fieldIndex}.parseMode`}
                                            label={t_i18n('Parse mode')}
                                            fullWidth={true}
                                            containerstyle={{ width: '100%', marginTop: 20 }}
                                            value={field.parseMode || 'comma'}
                                          >
                                            <MenuItem value="comma">{t_i18n('Comma-separated')}</MenuItem>
                                            {field.type === 'textarea' && (
                                              <MenuItem value="line">{t_i18n('One per line')}</MenuItem>
                                            )}
                                          </Field>
                                          )}
                                        </div>
                                      );
                                    })}

                                    <Button
                                      variant="contained"
                                      color="primary"
                                      startIcon={<Add />}
                                      className={classes.addFieldButton}
                                      onClick={() => {
                                        const newField: FormFieldAttribute = {
                                          id: generateFieldId(),
                                          name: '',
                                          type: 'text',
                                          required: false,
                                          attributeMapping: {
                                            entity: entity.id,
                                            attribute: '',
                                          },
                                          ...(entity.multiple ? { fieldMode: 'multi' } : {}),
                                        };
                                        pushField(newField);
                                      }}
                                    >
                                      {t_i18n('Add Field to')} {entity.name || t_i18n('Entity')}
                                    </Button>
                                  </>
                                )}
                              </FieldArray>
                            )}
                          </div>
                        );
                      })}

                      <Button
                        variant="contained"
                        color="secondary"
                        startIcon={<Add />}
                        className={classes.addEntityButton}
                        onClick={() => {
                          const newEntity: AdditionalEntity = {
                            id: generateEntityId(),
                            type: 'Malware',
                            name: `${t_i18n('Entity')} ${values.additionalEntities.length + 1}`,
                            multiple: false,
                          };
                          pushEntity(newEntity);
                        }}
                      >
                        {t_i18n('Add Additional Entity')}
                      </Button>
                    </>
                  )}
                </FieldArray>
              </div>
            )}

            {currentTab === 1 && (
              <div className={classes.tabContent}>
                <Typography variant="h6" gutterBottom>
                  {t_i18n('Define Relationships Between Entities')}
                </Typography>

                <FieldArray name="relationships">
                  {({ push, remove }) => (
                    <>
                      {values.relationships.map((relationship, index) => {
                        const allEntities = [
                          { id: 'main_entity', label: `${t_i18n('Main Entity')} (${mainEntityInfo?.label})` },
                          ...values.additionalEntities.map((e) => ({
                            id: e.id,
                            label: `${e.name} (${entityTypes.find((t) => t.value === e.type)?.label})`,
                          })),
                        ];

                        const fromEntity = relationship.from === 'main_entity'
                          ? values.mainEntityType
                          : values.additionalEntities.find((e) => e.id === relationship.from)?.type;
                        const toEntity = relationship.to === 'main_entity'
                          ? values.mainEntityType
                          : values.additionalEntities.find((e) => e.id === relationship.to)?.type;

                        return (
                          <div key={relationship.id} className={classes.relationshipGroup}>
                            <div className={classes.fieldHeader}>
                              <Typography className={classes.fieldTitle}>
                                {t_i18n('Relationship')} {index + 1}
                              </Typography>
                              <IconButton
                                size="small"
                                color="primary"
                                onClick={() => remove(index)}
                              >
                                <DeleteOutlined />
                              </IconButton>
                            </div>

                            <Field
                              component={SelectField}
                              variant="standard"
                              name={`relationships.${index}.from`}
                              label={t_i18n('From Entity')}
                              fullWidth={true}
                              containerstyle={{ width: '100%' }}
                              onChange={(__: never, _value: any) => {
                                // Reset relationship type when from entity changes
                                setFieldValue(`relationships.${index}.type`, '');
                              }}
                            >
                              {allEntities.map((entity) => (
                                <MenuItem key={entity.id} value={entity.id}>
                                  {entity.label}
                                </MenuItem>
                              ))}
                            </Field>

                            <Field
                              component={SelectField}
                              variant="standard"
                              name={`relationships.${index}.type`}
                              label={t_i18n('Relationship Type')}
                              fullWidth={true}
                              containerstyle={{ width: '100%', marginTop: 20 }}
                            >
                              {fromEntity && toEntity
                                && getAvailableRelationships(fromEntity, toEntity).map((type) => (
                                  <MenuItem key={type.value} value={type.value}>
                                    {type.label}
                                  </MenuItem>
                                ))}
                            </Field>

                            <Field
                              component={SelectField}
                              variant="standard"
                              name={`relationships.${index}.to`}
                              label={t_i18n('To Entity')}
                              fullWidth={true}
                              containerstyle={{ width: '100%', marginTop: 20 }}
                              onChange={(__: never, _value: any) => {
                                // Reset relationship type when to entity changes
                                setFieldValue(`relationships.${index}.type`, '');
                              }}
                            >
                              {allEntities.map((entity) => (
                                <MenuItem key={entity.id} value={entity.id}>
                                  {entity.label}
                                </MenuItem>
                              ))}
                            </Field>
                          </div>
                        );
                      })}

                      <Button
                        variant="contained"
                        color="primary"
                        startIcon={<Add />}
                        className={classes.addFieldButton}
                        onClick={() => {
                          const newRelationship: EntityRelationship = {
                            id: generateRelationshipId(),
                            from: 'main_entity',
                            to: values.additionalEntities[0]?.id || 'main_entity',
                            type: 'related-to',
                          };
                          push(newRelationship);
                        }}
                        disabled={values.additionalEntities.length === 0}
                      >
                        {t_i18n('Add Relationship')}
                      </Button>

                      {values.additionalEntities.length === 0 && (
                        <Typography variant="body2" style={{ marginTop: 10, fontStyle: 'italic' }}>
                          {t_i18n('Add additional entities first to define relationships')}
                        </Typography>
                      )}
                    </>
                  )}
                </FieldArray>
              </div>
            )}

            <div className={classes.buttons}>
              <Button
                variant="contained"
                onClick={handleReset}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                variant="contained"
                color="secondary"
                onClick={submitForm}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t_i18n('Create')}
              </Button>
            </div>
          </Form>
        );
      }}
    </Formik>
  );
};

interface FormCreationContainerProps {
  paginationOptions: FormLinesPaginationQuery$variables;
}

// Custom controlled dial for Forms
const CreateFormControlledDial = (props: any) => {
  return <CreateEntityControlledDial {...props} entityType="Form" />;
};

export const FormCreationContainer: FunctionComponent<FormCreationContainerProps> = ({ paginationOptions }) => {
  const { t_i18n } = useFormatter();
  const formCreationRef = useQueryLoading<FormCreationQuery>(formCreationQuery);
  return (
    <Drawer
      controlledDial={CreateFormControlledDial}
      title={t_i18n('Create a form')}
    >
      {({ onClose }) => (
        <Suspense fallback={<Loader />}>
          {formCreationRef && (
            <FormCreation
              handleClose={onClose}
              paginationOptions={paginationOptions}
              queryRef={formCreationRef}
            />
          )}
        </Suspense>
      )}
    </Drawer>
  );
};

export default FormCreation;
