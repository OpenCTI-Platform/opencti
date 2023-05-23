import React from 'react';
import { ArrowRightAlt } from '@mui/icons-material';
import Button from '@mui/material/Button';
import { Field, Form, Formik } from 'formik';
import makeStyles from '@mui/styles/makeStyles';
import * as Yup from 'yup';
import { SimpleFileUpload } from 'formik-mui';
import { itemColor } from '../../../../utils/Colors';
import ItemIcon from '../../../../components/ItemIcon';
import { truncate } from '../../../../utils/String';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import MarkDownField from '../../../../components/MarkDownField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import SwitchField from '../../../../components/SwitchField';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';

const useStyles = makeStyles((theme) => ({
  containerRelation: {
    padding: '10px 20px 20px 20px',
  },
  item: {
    position: 'absolute',
    width: 180,
    height: 80,
    borderRadius: 10,
  },
  itemHeader: {
    padding: '10px 0',
  },
  icon: {
    position: 'absolute',
    top: 8,
    left: 5,
    fontSize: 8,
  },
  type: {
    width: '100%',
    textAlign: 'center',
    color: theme.palette.text.primary,
    fontSize: 11,
  },
  content: {
    width: '100%',
    height: 40,
    maxHeight: 40,
    lineHeight: '40px',
    color: theme.palette.text.primary,
    textAlign: 'center',
  },
  name: {
    display: 'inline-block',
    lineHeight: 1,
    fontSize: 12,
    verticalAlign: 'middle',
  },
  relationCreate: {
    position: 'relative',
    height: 100,
  },
  middle: {
    margin: '0 auto',
    width: 200,
    textAlign: 'center',
    padding: 0,
    color: theme.palette.text.primary,
  },
  buttonBack: {
    marginTop: 20,
    float: 'left',
  },
  buttons: {
    marginTop: 20,
    float: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const StixSightingRelationshipCreationForm = ({
  fromEntities,
  toEntities,
  handleReverseRelation,
  handleResetSelection,
  onSubmit,
  handleClose,
  defaultConfidence,
  defaultFirstSeen,
  defaultLastSeen,
  defaultCreatedBy,
  defaultMarkingDefinitions,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const basicShape = {
    attribute_count: Yup.number()
      .typeError(t('The value must be a number'))
      .integer(t('The value must be a number'))
      .required(t('This field is required')),
    confidence: Yup.number().required(t('This field is required')),
    first_seen: Yup.date()
      .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .nullable(),
    last_seen: Yup.date()
      .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .nullable(),
    description: Yup.string().nullable(),
    x_opencti_negative: Yup.boolean(),
  };
  const stixSightingRelationshipValidator = useSchemaCreationValidation('stix-sighting-relationship', basicShape);

  const fromEntity = fromEntities[0];
  const toEntity = toEntities[0];
  const isMultipleFrom = fromEntities.length > 1;
  const isMultipleTo = toEntities.length > 1;

  const defaultName = (entity) => truncate(
    // eslint-disable-next-line no-nested-ternary
    (entity.parent_types.includes('Stix-Cyber-Observable')
      ? entity.observable_value
      : entity.entity_type === 'stix_relation'
        ? `${entity.from.name} ${String.fromCharCode(8594)} ${entity.to.name}`
        : entity.name),
    20,
  );

  const initialValues = {
    attribute_count: 1,
    confidence: defaultConfidence ?? 75,
    first_seen: defaultFirstSeen,
    last_seen: defaultLastSeen,
    description: '',
    externalReferences: [],
    objectMarking: defaultMarkingDefinitions ?? [],
    createdBy: defaultCreatedBy ?? '',
    x_opencti_negative: false,
    file: undefined,
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={stixSightingRelationshipValidator}
      onSubmit={onSubmit}
      onReset={handleClose}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
        <Form style={{ paddingBottom: 50 }}>
          <div className={classes.containerRelation}>
            <div className={classes.relationCreate}>
              <div
                className={classes.item}
                style={{
                  border: `2px solid ${itemColor(fromEntity.entity_type)}`,
                  top: 10,
                  left: 0,
                }}
              >
                <div
                  className={classes.itemHeader}
                  style={{
                    borderBottom: `1px solid ${itemColor(fromEntity.entity_type)}`,
                  }}
                >
                  <div className={classes.icon}>
                    <ItemIcon
                      type={fromEntity.entity_type}
                      color={itemColor(fromEntity.entity_type)}
                      size="small"
                    />
                  </div>
                  <div className={classes.type}>
                    {fromEntity.relationship_type
                      ? t(`relationship_${fromEntity.entity_type}`)
                      : t(`entity_${fromEntity.entity_type}`)}
                  </div>
                </div>
                <div className={classes.content}>
                  <span className={classes.name}>
                    {isMultipleFrom
                      ? (<em>{t('Multiple entities selected')}</em>)
                      : (defaultName(fromEntity))}
                  </span>
                </div>
              </div>
              <div className={classes.middle} style={{ paddingTop: 25 }}>
                <ArrowRightAlt fontSize="large" />
                <br />
                {typeof handleReverseRelation === 'function' && (
                  <Button
                    variant="outlined"
                    onClick={handleReverseRelation}
                    color="secondary"
                    size="small"
                  >
                    {t('Reverse')}
                  </Button>
                )}
              </div>
              <div
                className={classes.item}
                style={{
                  border: `2px solid ${itemColor(toEntity.entity_type)}`,
                  top: 10,
                  right: 0,
                }}
              >
                <div
                  className={classes.itemHeader}
                  style={{
                    borderBottom: `1px solid ${itemColor(toEntity.entity_type)}`,
                  }}
                >
                  <div className={classes.icon}>
                    <ItemIcon
                      type={toEntity.entity_type}
                      color={itemColor(toEntity.entity_type)}
                      size="small"
                    />
                  </div>
                  <div className={classes.type}>
                    {toEntity.relationship_type
                      ? t(`relationship_${toEntity.entity_type}`)
                      : t(`entity_${toEntity.entity_type}`)}
                  </div>
                </div>
                <div className={classes.content}>
                  <span className={classes.name}>
                    {isMultipleTo
                      ? (<em>{t('Multiple entities selected')}</em>)
                      : (defaultName(toEntity))}
                  </span>
                </div>

              </div>
            </div>
            <Field
              component={TextField}
              variant="standard"
              name="attribute_count"
              label={t('Count')}
              fullWidth={true}
              type="number"
              style={{ marginTop: 20 }}
            />
            <ConfidenceField
              entityType="stix-sighting-relationship"
              containerStyle={fieldSpacingContainerStyle}
            />
            <Field
              component={DateTimePickerField}
              name="first_seen"
              TextFieldProps={{
                label: t('First seen'),
                variant: 'standard',
                fullWidth: true,
                style: { marginTop: 20 },
              }}
            />
            <Field
              component={DateTimePickerField}
              name="last_seen"
              TextFieldProps={{
                label: t('Last seen'),
                variant: 'standard',
                fullWidth: true,
                style: { marginTop: 20 },
              }}
            />
            <Field
              component={MarkDownField}
              name="description"
              label={t('Description')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
            />
            <CreatedByField
              name="createdBy"
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
            <ObjectMarkingField
              name="objectMarking"
              style={fieldSpacingContainerStyle}
            />
            <Field
              component={SwitchField}
              type="checkbox"
              name="x_opencti_negative"
              label={t('False positive')}
              containerstyle={{ marginTop: 20 }}
            />
            <ExternalReferencesField
              name="externalReferences"
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
            <Field
              component={SimpleFileUpload}
              name="file"
              label={t('Associated file')}
              FormControlProps={{ style: { marginTop: 20, width: '100%' } }}
              InputLabelProps={{ fullWidth: true, variant: 'standard' }}
              InputProps={{ fullWidth: true, variant: 'standard' }}
              fullWidth={true}
            />
            {typeof handleResetSelection === 'function' && (
              <div className={classes.buttonBack}>
                <Button
                  variant="contained"
                  onClick={handleResetSelection}
                  disabled={isSubmitting}
                >
                  {t('Back')}
                </Button>
              </div>
            )}
            <div className={classes.buttons}>
              <Button
                variant="contained"
                onClick={handleReset}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t('Cancel')}
              </Button>
              <Button
                variant="contained"
                color="secondary"
                onClick={submitForm}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t('Create')}
              </Button>
            </div>
          </div>
        </Form>
      )}
    </Formik>
  );
};

export default StixSightingRelationshipCreationForm;
