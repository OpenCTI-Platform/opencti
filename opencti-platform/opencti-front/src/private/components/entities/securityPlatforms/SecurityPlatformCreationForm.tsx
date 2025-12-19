import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import React, { FunctionComponent, useEffect, useState } from 'react';
import { securityPlatformCreationMutation } from '@components/entities/securityPlatforms/SecurityPlatformCreation';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import {
  SecurityPlatformCreationMutation,
  SecurityPlatformCreationMutation$variables,
} from '@components/entities/securityPlatforms/__generated__/SecurityPlatformCreationMutation.graphql';
import { FormikConfig } from 'formik/dist/types';
import OpenVocabField from '@components/common/form/OpenVocabField';
import CreatedByField from '@components/common/form/CreatedByField';
import ObjectLabelField from '@components/common/form/ObjectLabelField';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import { getSecurityPlatformValidator, SECURITY_PLATFORM_TYPE } from '@components/entities/securityPlatforms/SecurityPlatformUtils';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useBulkCommit from '../../../../utils/hooks/useBulkCommit';
import { splitMultilines } from '../../../../utils/String';
import { handleErrorInForm } from '../../../../relay/environment';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import BulkTextModal from '../../../../components/fields/BulkTextField/BulkTextModal';
import ProgressBar from '../../../../components/ProgressBar';
import BulkTextField from '../../../../components/fields/BulkTextField/BulkTextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { useIsMandatoryAttribute } from '../../../../utils/hooks/useEntitySettings';

interface SecurityPlatformCreationFormData {
  name: string;
  description: string;
  security_platform_type: string | undefined;
  createdBy: FieldOption | undefined;
  objectLabel: FieldOption[];
  objectMarking: FieldOption[];
}

interface SecurityPlatformCreationFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: FieldOption;
  defaultMarkingDefinitions?: FieldOption[];
  inputValue?: string;
  bulkModalOpen?: boolean;
  onBulkModalClose: () => void;
}

const SecurityPlatformCreationForm: FunctionComponent<SecurityPlatformCreationFormProps> = ({
  updater,
  onReset,
  onCompleted,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  bulkModalOpen = false,
  onBulkModalClose,
  inputValue,
}) => {
  const { t_i18n } = useFormatter();
  const [progressBarOpen, setProgressBarOpen] = useState(false);
  const { mandatoryAttributes } = useIsMandatoryAttribute(SECURITY_PLATFORM_TYPE);
  const securityPlatformValidator = getSecurityPlatformValidator(mandatoryAttributes);

  const [commit] = useApiMutation<SecurityPlatformCreationMutation>(
    securityPlatformCreationMutation,
    undefined,
    { successMessage: `${t_i18n('entity_SecurityPlatform')} ${t_i18n('successfully created')}` },
  );

  const {
    bulkCommit,
    bulkCount,
    bulkCurrentCount,
    BulkResult,
    resetBulk,
  } = useBulkCommit<SecurityPlatformCreationMutation>({
    commit,
    relayUpdater: (store) => {
      if (updater) {
        updater(store, 'securityPlatformAdd');
      }
    },
  });

  useEffect(() => {
    if (bulkCount > 1) {
      setProgressBarOpen(true);
    }
  }, [bulkCount]);

  const onSubmit: FormikConfig<SecurityPlatformCreationFormData>['onSubmit'] = (values, {
    setSubmitting,
    setErrors,
    resetForm,
  }) => {
    const allNames = splitMultilines(values.name);
    const variables: SecurityPlatformCreationMutation$variables[] = allNames.map((name) => ({
      input: {
        name,
        description: values.description,
        security_platform_type: values.security_platform_type,
        createdBy: values.createdBy?.value,
        objectMarking: values.objectMarking.map((v) => v.value),
        objectLabel: values.objectLabel.map((v) => v.value),
      },
    }));

    bulkCommit({
      variables,
      onStepError: (error) => {
        handleErrorInForm(error, setErrors);
      },
      onCompleted: (total: number) => {
        setSubmitting(false);
        if (total < 2) {
          resetForm();
          onCompleted?.();
        }
      },
    });
  };

  const initialValues = useDefaultValues(
    SECURITY_PLATFORM_TYPE,
    {
      name: inputValue ?? '',
      description: '',
      security_platform_type: undefined,
      createdBy: defaultCreatedBy ?? undefined, // undefined for Require Fields Flagging, if Configured Mandatory Field
      objectMarking: defaultMarkingDefinitions ?? [],
      objectLabel: [],
    },
  );

  return (
    <Formik<SecurityPlatformCreationFormData>
      initialValues={initialValues}
      validationSchema={securityPlatformValidator}
      validateOnChange={false}
      validateOnBlur={false}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({
        submitForm,
        handleReset,
        isSubmitting,
        setFieldValue,
        values,
        resetForm,
      }) => (
        <>
          <BulkTextModal
            open={bulkModalOpen}
            onClose={onBulkModalClose}
            onValidate={async (val) => {
              await setFieldValue('name', val);
              if (splitMultilines(val).length > 1) {
                await setFieldValue('file', null);
              }
            }}
            formValue={values.name}
          />
          <ProgressBar
            open={progressBarOpen}
            value={(bulkCurrentCount / bulkCount) * 100}
            label={`${bulkCurrentCount}/${bulkCount}`}
            title={t_i18n('Create multiple entities')}
            onClose={() => {
              setProgressBarOpen(false);
              resetForm();
              resetBulk();
              onCompleted?.();
            }}
          >
            <BulkResult variablesToString={(v) => v.input.name} />
          </ProgressBar>
          <Form>
            <Field
              component={BulkTextField}
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              required={(mandatoryAttributes.includes('name'))}
              fullWidth={true}
              detectDuplicate={['securityPlatform']}
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              required={(mandatoryAttributes.includes('description'))}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={fieldSpacingContainerStyle}
            />
            { /* TODO Improve customization (vocab with letter range) 2662 */}
            <OpenVocabField
              label={t_i18n('Security platform type')}
              type="security_platform_type_ov"
              name="security_platform_type"
              required={(mandatoryAttributes.includes('security_platform_type'))}
              containerStyle={fieldSpacingContainerStyle}
              multiple={false}
              onChange={setFieldValue}
            />
            <CreatedByField
              name="createdBy"
              required={(mandatoryAttributes.includes('createdBy'))}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
            <ObjectLabelField
              name="objectLabel"
              required={(mandatoryAttributes.includes('objectLabel'))}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
              values={values.objectLabel}
            />
            <ObjectMarkingField
              name="objectMarking"
              required={(mandatoryAttributes.includes('objectMarking'))}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
            <div style={{
              marginTop: '20px',
              textAlign: 'right',
            }}
            >
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
                sx={{ marginLeft: 2 }}
              >
                {t_i18n('Create')}
              </Button>
            </div>
          </Form>
        </>
      )}
    </Formik>
  );
};

export default SecurityPlatformCreationForm;
