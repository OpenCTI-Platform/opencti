import React from 'react';
import { Field, Form, Formik } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import { ArrowRightAlt } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import * as R from 'ramda';
import SelectField from '../../../../components/SelectField';
import ConfidenceField from '../form/ConfidenceField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import MarkdownField from '../../../../components/MarkdownField';
import { hasKillChainPhase } from '../../../../utils/Relation';
import KillChainPhasesField from '../form/KillChainPhasesField';
import CreatedByField from '../form/CreatedByField';
import ObjectMarkingField from '../form/ObjectMarkingField';
import { isNone, useFormatter } from '../../../../components/i18n';
import { ExternalReferencesField } from '../form/ExternalReferencesField';
import { itemColor } from '../../../../utils/Colors';
import ItemIcon from '../../../../components/ItemIcon';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
    textOverflow: 'ellipsis',
    maxWidth: 180,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    padding: 8,
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

export const stixCoreRelationshipBasicShape = (t) => ({
  relationship_type: Yup.string().required(t('This field is required')),
  confidence: Yup.number().nullable(),
  start_time: Yup.date()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .nullable(),
  stop_time: Yup.date()
    .min(Yup.ref('start_time'), "The end date can't be before start date")
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .nullable(),
  description: Yup.string().nullable(),
});

const STIX_CORE_RELATIONSHIP_TYPE = 'stix-core-relationship';

const StixCoreRelationshipCreationForm = ({
  fromEntities,
  toEntities,
  relationshipTypes,
  handleReverseRelation,
  handleResetSelection,
  onSubmit,
  createAnother,
  defaultConfidence,
  defaultStartTime,
  defaultStopTime,
  defaultCreatedBy,
  defaultMarkingDefinitions,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const stixCoreRelationshipValidator = useSchemaCreationValidation(STIX_CORE_RELATIONSHIP_TYPE, stixCoreRelationshipBasicShape(t_i18n));

  const fromEntity = fromEntities[0];
  const toEntity = toEntities[0];
  const isMultipleFrom = fromEntities.length > 1;
  const isMultipleTo = toEntities.length > 1;

  // eslint-disable-next-line no-nested-ternary
  const defaultRelationshipType = R.head(relationshipTypes)
    ? R.head(relationshipTypes)
    : relationshipTypes.includes('related-to')
      ? 'related-to'
      : '';

  const initialValues = useDefaultValues(
    STIX_CORE_RELATIONSHIP_TYPE,
    {
      relationship_type: defaultRelationshipType,
      confidence: defaultConfidence,
      start_time: !isNone(defaultStartTime) ? defaultStartTime : null,
      stop_time: !isNone(defaultStopTime) ? defaultStopTime : null,
      description: '',
      killChainPhases: [],
      externalReferences: [],
      objectMarking: defaultMarkingDefinitions ?? [],
      createdBy: defaultCreatedBy ?? '',
    },
  );

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={stixCoreRelationshipValidator}
      onSubmit={onSubmit}
    >
      {({ submitForm, isSubmitting, setFieldValue, values }) => (
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
                      ? t_i18n(`relationship_${fromEntity.entity_type}`)
                      : t_i18n(`entity_${fromEntity.entity_type}`)}
                  </div>
                </div>
                <div className={classes.content}>
                  <span className={classes.name}>
                    {isMultipleFrom
                      ? (<em>{t_i18n('Multiple entities selected')}</em>)
                      : (getMainRepresentative(fromEntity))}
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
                    {t_i18n('Reverse')}
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
                      ? t_i18n(`relationship_${toEntity.entity_type}`)
                      : t_i18n(`entity_${toEntity.entity_type}`)}
                  </div>
                </div>
                <div className={classes.content}>
                  <span className={classes.name}>
                    {isMultipleTo
                      ? (<em>{t_i18n('Multiple entities selected')}</em>)
                      : (getMainRepresentative(toEntity))}
                  </span>
                </div>
              </div>
            </div>
            <Field
              component={SelectField}
              variant="standard"
              name="relationship_type"
              label={t_i18n('Relationship type')}
              fullWidth={true}
              containerstyle={fieldSpacingContainerStyle}
            >
              {relationshipTypes.map(
                (type) => (
                  <MenuItem key={type} value={type}>
                    {t_i18n(`relationship_${type}`)}
                  </MenuItem>
                ),
              )}
            </Field>
            <ConfidenceField
              entityType="stix-core-relationship"
              containerStyle={fieldSpacingContainerStyle}
            />
            <Field
              component={DateTimePickerField}
              name="start_time"
              textFieldProps={{
                label: t_i18n('Start time'),
                variant: 'standard',
                fullWidth: true,
                style: { marginTop: 20 },
              }}
            />
            <Field
              component={DateTimePickerField}
              name="stop_time"
              textFieldProps={{
                label: t_i18n('Stop time'),
                variant: 'standard',
                fullWidth: true,
                style: { marginTop: 20 },
              }}
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={fieldSpacingContainerStyle}
            />
            {hasKillChainPhase(values.relationship_type) ? (
              <KillChainPhasesField
                name="killChainPhases"
                style={fieldSpacingContainerStyle}
              />
            ) : (
              ''
            )}
            <CreatedByField
              name="createdBy"
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
            <ObjectMarkingField
              name="objectMarking"
              style={fieldSpacingContainerStyle}
            />
            <ExternalReferencesField
              name="externalReferences"
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
            {typeof handleResetSelection === 'function' && (
              <div className={classes.buttonBack}>
                <Button
                  variant="outlined"
                  onClick={handleResetSelection}
                  disabled={isSubmitting}
                >
                  {t_i18n('Back')}
                </Button>
              </div>
            )}
            <div className={classes.buttons}>
              {/* <Button
                variant="outlined"
                onClick={(e) => {
                  if (typeof createAnother === 'function') {
                    createAnother(true);
                  }
                  submitForm(e);
                }}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t_i18n('Create and Create Another')}
              </Button> */}
              <Button
                variant="contained"
                color="primary"
                onClick={(e) => {
                  if (typeof createAnother === 'function') {
                    createAnother(false);
                  }
                  submitForm(e);
                }}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t_i18n('Create and Finish')}
              </Button>
            </div>
          </div>
        </Form>
      )}
    </Formik>
  );
};

export default StixCoreRelationshipCreationForm;
