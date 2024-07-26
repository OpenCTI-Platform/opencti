import { Button, MenuItem, useTheme } from '@mui/material';
import { Field, Form, Formik, FormikHelpers } from 'formik';
import React, { FunctionComponent } from 'react';
import DateTimePickerField from 'src/components/DateTimePickerField';
import SelectField from 'src/components/fields/SelectField';
import { useFormatter } from 'src/components/i18n';
import { itemColor } from 'src/utils/Colors';
import { dayStartDate } from 'src/utils/Time';
import { fieldSpacingContainerStyle } from 'src/utils/field';
import * as Yup from 'yup';
import ItemIcon from 'src/components/ItemIcon';
import { truncate } from 'src/utils/String';
import { getMainRepresentative } from 'src/utils/defaultRepresentatives';
import { ArrowRightAlt } from '@mui/icons-material';
import { TargetEntity } from '../stix_core_relationships/StixCoreRelationshipCreationFromEntity';

const RelationshipCard = ({ entity, multiple = false }: {
  entity: TargetEntity,
  multiple?: boolean,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const color = itemColor(entity.entity_type);

  return (
    <div
      style={{
        width: 180,
        height: 80,
        borderRadius: 10,
        border: `2px solid ${color}`,
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      <div
        style={{
          padding: '10px 0 10px 0',
          borderBottom: `1px solid ${color}`,
          width: '100%',
          display: 'flex',
          flexDirection: 'row',
          alignItems: 'center',
        }}
      >
        <div
          style={{
            fontSize: 8,
            float: 'left',
            margin: '0 -25px 0 5px',
          }}
        >
          <ItemIcon
            type={entity.entity_type}
            color={color}
            size="small"
          />
        </div>
        <div
          style={{
            width: '100%',
            textAlign: 'center',
            color: theme.palette.text.primary,
            fontSize: 11,
          }}
        >
          {t_i18n(`entity_${entity.entity_type}`)}
        </div>
      </div>
      <div
        style={{
          width: '100%',
          height: 40,
          maxHeight: 40,
          lineHeight: '30px',
          color: theme.palette.text.primary,
          textAlign: 'center',
        }}
      >
        <span
          style={{
            display: 'inline-block',
            lineHeight: 1,
            fontSize: 12,
            verticalAlign: 'middle',
          }}
        >
          {multiple
            ? <em>{t_i18n('Multiple entities selected')}</em>
            : truncate(getMainRepresentative(entity), 20)
          }
        </span>
      </div>
    </div>
  );
};

export interface StixNestedRefRelationshipCreationFormValues {
  from_id: string,
  to_ids: string[],
  relationship_type: string,
  start_time: string,
  stop_time: string,
}

interface StixNestedRefRelationshipCreationFormProps {
  sourceEntity: TargetEntity,
  targetEntities: TargetEntity[],
  relationshipTypes: string[],
  defaultStartTime?: string,
  defaultStopTime?: string,
  onSubmit: (values: StixNestedRefRelationshipCreationFormValues, helpers: FormikHelpers<StixNestedRefRelationshipCreationFormValues>) => void,
  handleClose: () => void,
  handleBack: () => void,
  handleReverse?: () => void,
}

const StixNestedRefRelationshipCreationForm: FunctionComponent<
StixNestedRefRelationshipCreationFormProps
> = ({
  sourceEntity,
  targetEntities,
  relationshipTypes,
  defaultStartTime,
  defaultStopTime,
  onSubmit,
  handleClose,
  handleBack,
  handleReverse,
}) => {
  if (targetEntities.length < 1) handleBack(); // Must have at least one target entity

  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const stixNestedRefRelationshipValidation = () => Yup.object().shape({
    relationship_type: Yup.string().required(t_i18n('This field is required')),
    start_time: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .required(t_i18n('This field is required')),
    stop_time: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .required(t_i18n('This field is required')),
  });

  const initialValues: StixNestedRefRelationshipCreationFormValues = {
    from_id: sourceEntity.id,
    to_ids: targetEntities.map((target) => target.id),
    relationship_type: relationshipTypes?.[0] ?? undefined,
    start_time: defaultStartTime ?? dayStartDate().toISOString(),
    stop_time: defaultStopTime ?? dayStartDate().toISOString(),
  };

  const targetEntity = targetEntities[0];

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={stixNestedRefRelationshipValidation}
      onSubmit={onSubmit}
    >
      {({ submitForm, isSubmitting }) => (
        <Form>
          <div style={{ padding: '10px 20px 20px 20px' }}>
            <div
              style={{
                position: 'relative',
                height: 100,
                display: 'flex',
                alignItems: 'center',
              }}
            >
              <RelationshipCard entity={sourceEntity} />
              <div
                style={{
                  margin: '0 auto',
                  width: 200,
                  textAlign: 'center',
                  padding: 0,
                  color: theme.palette.text.primary,
                }}
              >
                <ArrowRightAlt
                  fontSize="large"
                  style={{
                    paddingTop: 25,
                    margin: '0 auto',
                    width: 200,
                    textAlign: 'center',
                    padding: 0,
                    color: theme.palette.text.primary,
                  }}
                />
                <br />
                {typeof handleReverse === 'function' && (
                  <Button
                    variant="outlined"
                    onClick={handleReverse}
                    color="secondary"
                    size="small"
                  >
                    {t_i18n('Reverse')}
                  </Button>
                )}
              </div>
              <RelationshipCard
                entity={targetEntity}
                multiple={targetEntities.length > 1}
              />
            </div>
            <Field
              component={SelectField}
              variant="standard"
              name="relationship_type"
              label={t_i18n('Relationship type')}
              fullWidth={true}
              containerstyle={fieldSpacingContainerStyle}
            >
              {relationshipTypes.map((type) => (
                <MenuItem key={type} value={type}>
                  {t_i18n(`relationship_${type}`)}
                </MenuItem>
              ))}
            </Field>
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
            <Button
              variant="contained"
              onClick={handleBack}
              disabled={isSubmitting}
              style={{
                marginTop: 20,
                textAlign: 'left',
                float: 'left',
              }}
            >
              {t_i18n('Back')}
            </Button>
            <div style={{
              marginTop: 20,
              textAlign: 'right',
              float: 'right',
            }}
            >
              <Button
                variant="outlined"
                onClick={handleClose}
                disabled={isSubmitting}
                style={{ marginLeft: theme.spacing(2) }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                variant="contained"
                onClick={submitForm}
                disabled={isSubmitting}
                style={{ marginLeft: theme.spacing(2) }}
              >
                {t_i18n('Create')}
              </Button>
            </div>
          </div>
        </Form>
      )}
    </Formik>
  );
};

export default StixNestedRefRelationshipCreationForm;
