import { Option } from '@components/common/form/ReferenceField';
import * as Yup from 'yup';
import { Field, Form, Formik } from 'formik';
import React, { useEffect } from 'react';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import { CONTENT_MAX_MARKINGS_HELPERTEXT, CONTENT_MAX_MARKINGS_TITLE } from '@components/common/files/FileManager';
import { useParams } from 'react-router-dom';
import EntitySelectField from '@components/common/form/EntitySelectField';
import { EntityOption } from '@components/common/form/EntitySelect';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import { useFormatter } from '../../../../../components/i18n';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import { isEmptyObject } from '../../../../../utils/object';

interface FintelTemplatePreviewFormInputs {
  entity: EntityOption | null;
  contentMaxMarkings: Option[];
  fileMarkings: Option[];
}

interface FintelTemplatePreviewFormProps {
  onChange: (val: FintelTemplatePreviewFormInputs) => void
}

const FintelTemplatePreviewForm = ({
  onChange,
}: FintelTemplatePreviewFormProps) => {
  const { t_i18n } = useFormatter();
  const { subTypeId } = useParams<{ subTypeId?: string }>();

  if (!subTypeId) return <ErrorNotFound />;

  const validation = () => Yup.object().shape({
    entity: Yup.object().required(),
  });

  const initialValues: FintelTemplatePreviewFormInputs = {
    entity: null,
    contentMaxMarkings: [],
    fileMarkings: [],
  };

  return (
    <Formik<FintelTemplatePreviewFormInputs>
      initialValues={initialValues}
      validationSchema={validation}
      onSubmit={() => {}}
    >
      {({ setFieldValue, values, validateForm }) => {
        useEffect(() => {
          const validate = async () => {
            const isValid = isEmptyObject(await validateForm(values));
            if (isValid) onChange(values);
          };
          validate();
        }, [values]);

        return (
          <Form>
            <Field
              name="entity"
              component={EntitySelectField}
              types={[subTypeId]}
              label={t_i18n('Entity')}
            />
            <ObjectMarkingField
              name="contentMaxMarkings"
              label={t_i18n(CONTENT_MAX_MARKINGS_TITLE)}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
              limitToMaxSharing
              helpertext={t_i18n(CONTENT_MAX_MARKINGS_HELPERTEXT)}
            />
            <ObjectMarkingField
              name="fileMarkings"
              label={t_i18n('File marking definition levels')}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
          </Form>
        );
      }}
    </Formik>
  );
};

export default FintelTemplatePreviewForm;
