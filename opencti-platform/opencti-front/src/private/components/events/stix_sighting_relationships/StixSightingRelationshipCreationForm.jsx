import React from 'react';
import { ArrowRightAlt } from '@mui/icons-material';
import Button from '@common/button/Button';
import { Field, Form } from 'formik';
import { styled } from '@mui/material/styles';
import * as Yup from 'yup';
import Tooltip from '@mui/material/Tooltip';
import { itemColor } from '../../../../utils/Colors';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import MarkdownField from '../../../../components/fields/markdownField/MarkdownField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import SwitchField from '../../../../components/fields/SwitchField';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import CustomFieldsFormik from '../../common/custom_fields/CustomFieldsFormik';
import CustomFieldValuesCreation from '../../common/custom_fields/CustomFieldValuesCreation';

const ContainerRelation = styled('div')({
  padding: '10px 20px 20px 20px',
});

const Item = styled('div')({
  position: 'absolute',
  width: 180,
  height: 80,
  borderRadius: 10,
});

const ItemHeader = styled('div')({
  padding: '10px 0',
});

const IconContainer = styled('div')({
  position: 'absolute',
  top: 8,
  left: 5,
  fontSize: 8,
});

const Type = styled('div')(({ theme }) => ({
  width: '100%',
  textAlign: 'center',
  color: theme.palette.text.primary,
  fontSize: 11,
}));

const Content = styled('div')(({ theme }) => ({
  width: '100%',
  height: 40,
  maxHeight: 40,
  lineHeight: '40px',
  color: theme.palette.text.primary,
  textAlign: 'center',
}));

const Name = styled('span')({
  display: 'inline-block',
  lineHeight: 1,
  fontSize: 12,
  verticalAlign: 'middle',
  textOverflow: 'ellipsis',
  maxWidth: 180,
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  padding: 8,
});

const RelationCreate = styled('div')({
  position: 'relative',
  height: 100,
});

const Middle = styled('div')(({ theme }) => ({
  margin: '0 auto',
  width: 200,
  textAlign: 'center',
  padding: 0,
  color: theme.palette.text.primary,
}));

const STIX_SIGHTING_TYPE = 'stix-sighting-relationship';

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
  const { t_i18n } = useFormatter();
  const { mandatoryAttributes } = useIsMandatoryAttribute(STIX_SIGHTING_TYPE);
  const basicShape = yupShapeConditionalRequired({
    attribute_count: Yup.number(),
    confidence: Yup.number().nullable(),
    first_seen: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .nullable(),
    last_seen: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .min(Yup.ref('first_seen'), "The end date can't be before start date")
      .nullable(),
    description: Yup.string().nullable(),
    x_opencti_negative: Yup.boolean().nullable(),
  }, mandatoryAttributes);
  const stixSightingRelationshipValidator = useDynamicSchemaCreationValidation(mandatoryAttributes, basicShape);

  const fromEntity = fromEntities[0];
  const toEntity = toEntities[0];
  const isMultipleFrom = fromEntities.length > 1;
  const isMultipleTo = toEntities.length > 1;

  const initialValues = useDefaultValues(
    STIX_SIGHTING_TYPE,
    {
      attribute_count: 1,
      confidence: defaultConfidence,
      first_seen: defaultFirstSeen,
      last_seen: defaultLastSeen,
      description: '',
      objectMarking: defaultMarkingDefinitions ?? [],
      createdBy: defaultCreatedBy ?? '',
      x_opencti_negative: undefined,
      externalReferences: [],
    },
    { x_opencti_negative: false },
  );

  return (
    <CustomFieldsFormik
      entityType={STIX_SIGHTING_TYPE}
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={stixSightingRelationshipValidator}
      validateOnBlur={true}
      validateOnChange={true}
      onSubmit={onSubmit}
      onReset={handleClose}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
        <Form style={{ paddingBottom: 50 }}>
          <ContainerRelation>
            <RelationCreate>
              <Item
                style={{
                  border: `2px solid ${itemColor(fromEntity?.entity_type)}`,
                  top: 10,
                  left: 0,
                }}
              >
                <ItemHeader
                  style={{
                    borderBottom: `1px solid ${itemColor(fromEntity?.entity_type)}`,
                  }}
                >
                  <IconContainer>
                    <ItemIcon
                      type={fromEntity?.entity_type}
                      color={itemColor(fromEntity?.entity_type)}
                      size="small"
                    />
                  </IconContainer>
                  <Type>
                    {fromEntity?.relationship_type
                      ? t_i18n(`relationship_${fromEntity?.entity_type}`)
                      : t_i18n(`entity_${fromEntity?.entity_type}`)}
                  </Type>
                </ItemHeader>
                <Content>
                  {isMultipleFrom ? (
                    <Name>
                      <em>{t_i18n('Multiple entities selected')}</em>
                    </Name>
                  ) : (
                    <Tooltip title={getMainRepresentative(fromEntity)}>
                      <Name>
                        {getMainRepresentative(fromEntity)}
                      </Name>
                    </Tooltip>
                  )}
                </Content>
              </Item>
              <Middle style={{ paddingTop: 25 }}>
                <ArrowRightAlt fontSize="large" />
                <br />
                {typeof handleReverseRelation === 'function' && (
                  <Button
                    variant="secondary"
                    onClick={handleReverseRelation}
                    size="small"
                  >
                    {t_i18n('Reverse')}
                  </Button>
                )}
              </Middle>
              <Item
                style={{
                  border: `2px solid ${itemColor(toEntity?.entity_type)}`,
                  top: 10,
                  right: 0,
                }}
              >
                <ItemHeader
                  style={{
                    borderBottom: `1px solid ${itemColor(toEntity?.entity_type)}`,
                  }}
                >
                  <IconContainer>
                    <ItemIcon
                      type={toEntity?.entity_type}
                      color={itemColor(toEntity?.entity_type)}
                      size="small"
                    />
                  </IconContainer>
                  <Type>
                    {toEntity?.relationship_type
                      ? t_i18n(`relationship_${toEntity?.entity_type}`)
                      : t_i18n(`entity_${toEntity?.entity_type}`)}
                  </Type>
                </ItemHeader>
                <Content>
                  {isMultipleTo ? (
                    <Name>
                      <em>{t_i18n('Multiple entities selected')}</em>
                    </Name>
                  ) : (
                    <Tooltip title={getMainRepresentative(toEntity)}>
                      <Name>
                        {getMainRepresentative(toEntity)}
                      </Name>
                    </Tooltip>
                  )}
                </Content>

              </Item>
            </RelationCreate>
            <Field
              component={TextField}
              variant="outlined"
              name="attribute_count"
              required={(mandatoryAttributes.includes('attribute_count'))}
              label={t_i18n('Count')}
              fullWidth={true}
              type="number"
              className="mt-5"
            />
            <ConfidenceField
              entityType="stix-sighting-relationship"
              containerStyle={fieldSpacingContainerStyle}
            />
            <Field
              component={DateTimePickerField}
              name="first_seen"
              textFieldProps={{
                label: t_i18n('First seen'),
                required: (mandatoryAttributes.includes('first_seen')),
                variant: 'outlined',
                fullWidth: true,
                style: { marginTop: 20 },
              }}
            />
            <Field
              component={DateTimePickerField}
              name="last_seen"
              textFieldProps={{
                label: t_i18n('Last seen'),
                required: (mandatoryAttributes.includes('last_seen')),
                variant: 'outlined',
                fullWidth: true,
                style: { marginTop: 20 },
              }}
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              required={(mandatoryAttributes.includes('description'))}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
            />
            <CreatedByField
              name="createdBy"
              required={(mandatoryAttributes.includes('createdBy'))}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
            <ObjectMarkingField
              name="objectMarking"
              required={(mandatoryAttributes.includes('objectMarking'))}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
            <Field
              component={SwitchField}
              type="checkbox"
              name="x_opencti_negative"
              label={t_i18n('False positive')}
              containerstyle={{ marginTop: 20 }}
            />
            <ExternalReferencesField
              name="externalReferences"
              required={(mandatoryAttributes.includes('externalReferences'))}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
            <CustomFieldValuesCreation />
            <FormButtonContainer>
              {typeof handleResetSelection === 'function' && (
                // A wrapper, not `sx`: the product Button falls back to MUI when given one.
                <div style={{ marginRight: 'auto' }}>
                  <Button
                    variant="secondary"
                    onClick={handleResetSelection}
                    disabled={isSubmitting}
                  >
                    {t_i18n('Back')}
                  </Button>
                </div>
              )}
              <Button
                variant="secondary"
                onClick={handleReset}
                disabled={isSubmitting}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                onClick={submitForm}
                disabled={isSubmitting}
              >
                {t_i18n('Create')}
              </Button>
            </FormButtonContainer>
          </ContainerRelation>
        </Form>
      )}
    </CustomFieldsFormik>
  );
};

export default StixSightingRelationshipCreationForm;
