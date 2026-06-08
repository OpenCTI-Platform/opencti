import Button from '@common/button/Button';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import { useRef, useState } from 'react';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import MarkdownField from '../../../../components/fields/markdownField/MarkdownField';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { insertNode } from '../../../../utils/store';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import FormButtonContainer from '@common/form/FormButtonContainer';
import Drawer from '@components/common/drawer/Drawer';

const artifactMutation = graphql`
  mutation ArtifactCreationMutation(
    $file: Upload!
    $x_opencti_description: String
    $createdBy: String
    $objectMarking: [String]
    $objectLabel: [String]
  ) {
    artifactImport(
      file: $file
      x_opencti_description: $x_opencti_description
      createdBy: $createdBy
      objectMarking: $objectMarking
      objectLabel: $objectLabel
    ) {
      id
      ...ArtifactsLine_node
    }
  }
`;

const artifactAddObservableMutation = graphql`
  mutation ArtifactCreationObservableMutation(
    $type: String!
    $x_opencti_description: String
    $createdBy: String
    $objectMarking: [String]
    $objectLabel: [String]
    $Artifact: ArtifactAddInput
  ) {
    stixCyberObservableAdd(
      type: $type
      x_opencti_description: $x_opencti_description
      createdBy: $createdBy
      objectMarking: $objectMarking
      objectLabel: $objectLabel
      Artifact: $Artifact
    ) {
      id
      ... on Artifact {
        ...ArtifactsLine_node
      }
    }
  }
`;

const artifactDescriptionPatchMutation = graphql`
  mutation ArtifactCreationDescriptionPatchMutation($id: ID!, $input: [EditInput]!) {
    stixCyberObservableEdit(id: $id) {
      fieldPatch(input: $input) {
        id
      }
    }
  }
`;

const artifactValidation = (t) => Yup.object().shape({
  file: Yup.mixed().nullable(),
  url: Yup.string().url(t('The value must be an URL')).nullable(),
  x_opencti_description: Yup.string().nullable(),
}).test('file-or-url', t('A file or a URL must be provided'), (values) => !!(values.file || values.url));

const ArtifactCreation = ({
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [commit] = useApiMutation(
    artifactMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Artifact')} ${t_i18n('successfully created')}` },
  );
  const [commitObservable] = useApiMutation(
    artifactAddObservableMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Artifact')} ${t_i18n('successfully created')}` },
  );
  const [commitDescriptionPatch] = useApiMutation(artifactDescriptionPatchMutation);
  const markdownControllerRef = useRef(null);

  const handleOpen = () => {
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
  };

  const onSubmit = (values, { setSubmitting, setErrors, resetForm }) => {
    const adaptedValues = R.evolve(
      {
        createdBy: R.path(['value']),
        objectMarking: R.pluck('value'),
        objectLabel: R.pluck('value'),
      },
      values,
    );

    if (values.file) {
      // File provided → use artifactImport
      commit({
        variables: {
          file: values.file,
          ...adaptedValues,
        },
        updater: (store) => insertNode(
          store,
          'Pagination_stixCyberObservables',
          paginationOptions,
          'artifactImport',
        ),
        onError: (error) => {
          handleErrorInForm(error, setErrors);
          setSubmitting(false);
        },
        onCompleted: async (response) => {
          try {
            const artifactId = response?.artifactImport?.id;
            const hasPendingMarkdownImages = (markdownControllerRef.current?.getPendingImageFiles().length ?? 0) > 0;

            if (artifactId && hasPendingMarkdownImages) {
              const finalizedDescription = await markdownControllerRef.current?.persistTempImages(artifactId);
              if (typeof finalizedDescription === 'string' && finalizedDescription !== values.x_opencti_description) {
                await new Promise((resolve, reject) => {
                  commitDescriptionPatch({
                    variables: {
                      id: artifactId,
                      input: [{ key: 'x_opencti_description', value: finalizedDescription }],
                    },
                    onCompleted: resolve,
                    onError: reject,
                  });
                });
              }
            }
          } finally {
            setSubmitting(false);
            resetForm();
            handleClose();
          }
        },
      });
    } else {
      // No file, only URL → use stixCyberObservableAdd
      commitObservable({
        variables: {
          type: 'Artifact',
          x_opencti_description: adaptedValues.x_opencti_description || null,
          createdBy: adaptedValues.createdBy || null,
          objectMarking: adaptedValues.objectMarking,
          objectLabel: adaptedValues.objectLabel,
          Artifact: { url: values.url },
        },
        updater: (store) => insertNode(
          store,
          'Pagination_stixCyberObservables',
          paginationOptions,
          'stixCyberObservableAdd',
        ),
        onError: (error) => {
          handleErrorInForm(error, setErrors);
          setSubmitting(false);
        },
        onCompleted: () => {
          setSubmitting(false);
          resetForm();
          handleClose();
        },
      });
    }
  };

  const onReset = () => {
    handleClose();
  };

  return (
    <>
      <CreateEntityControlledDial
        entityType="Artifact"
        onOpen={handleOpen}
      />
      <Drawer
        title={t_i18n('Create an artifact')}
        open={open}
        onClose={handleClose}
      >
        <Formik
          initialValues={{
            x_opencti_description: '',
            file: '',
            url: '',
            createdBy: '',
            objectMarking: [],
            objectLabel: [],
          }}
          validationSchema={artifactValidation(t_i18n)}
          onSubmit={onSubmit}
          onReset={onReset}
        >
          {({
            submitForm,
            handleReset,
            isSubmitting,
            setFieldValue,
            values,
            errors,
          }) => (
            <Form>
              <CustomFileUploader
                setFieldValue={setFieldValue}
                formikErrors={errors}
                noMargin
              />
              <Field
                component={TextField}
                variant="standard"
                name="url"
                label={t_i18n('URL')}
                fullWidth={true}
                style={{ marginTop: 20 }}
              />
              <Field
                component={MarkdownField}
                name="x_opencti_description"
                label={t_i18n('Description')}
                fullWidth={true}
                multiline={true}
                rows="4"
                style={{ marginTop: 20 }}
                autoPersistOnBlur={false}
                registerMarkdownImagesController={(controller) => {
                  markdownControllerRef.current = controller;
                }}
                uploadFileMarkings={values.objectMarking.map(({ value }) => value)}
              />
              <CreatedByField
                name="createdBy"
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
              />
              <ObjectLabelField
                name="objectLabel"
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
                values={values.objectLabel}
              />
              <ObjectMarkingField
                name="objectMarking"
                style={fieldSpacingContainerStyle}
              />
              <FormButtonContainer>
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
            </Form>
          )}
        </Formik>
      </Drawer>
    </>
  );
};

export default ArtifactCreation;
