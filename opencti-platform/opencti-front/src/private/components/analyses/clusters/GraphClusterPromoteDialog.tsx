import React from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { Switch, Text } from '@filigran/design-system';
import { Box } from '@mui/material';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/markdownField/MarkdownField';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle, type FieldOption } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { resolveLink } from '../../../../utils/Entity';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import type { GraphClusterPromoteDialogMutation, GraphClusterPromotionTarget } from './__generated__/GraphClusterPromoteDialogMutation.graphql';

const promoteMutation = graphql`
  mutation GraphClusterPromoteDialogMutation($id: ID!, $input: GraphClusterPromoteInput!) {
    graphClusterPromote(id: $id, input: $input) {
      id
      entity_type
    }
  }
`;

interface PromoteFormValues {
  name: string;
  description: string;
  createdBy: FieldOption | null;
  objectMarking: FieldOption[];
  include_features: boolean;
}

interface GraphClusterPromoteDialogProps {
  clusterId: string;
  clusterName: string;
  target: GraphClusterPromotionTarget;
  onClose: () => void;
}

/**
 * Explicit analyst action turning a computed cluster into knowledge: a Grouping containing the members (and optionally
 * the shared features), or a Campaign related to them. Only the members the analyst can access are used.
 */
const GraphClusterPromoteDialog = ({ clusterId, clusterName, target, onClose }: GraphClusterPromoteDialogProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [commit] = useApiMutation<GraphClusterPromoteDialogMutation>(promoteMutation, undefined, {
    successMessage: target === 'Grouping' ? t_i18n('Grouping created from the cluster') : t_i18n('Campaign created from the cluster'),
  });
  const validation = Yup.object().shape({
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
  });
  const initialValues: PromoteFormValues = {
    name: clusterName,
    description: '',
    createdBy: null,
    objectMarking: [],
    include_features: true,
  };
  const onSubmit = (values: PromoteFormValues, { setSubmitting }: { setSubmitting: (flag: boolean) => void }) => {
    commit({
      variables: {
        id: clusterId,
        input: {
          target,
          name: values.name.trim(),
          description: values.description,
          createdBy: values.createdBy?.value,
          objectMarking: values.objectMarking.map((marking) => marking.value),
          include_features: values.include_features,
        },
      },
      onCompleted: (response) => {
        setSubmitting(false);
        onClose();
        const created = response.graphClusterPromote;
        if (created) navigate(`${resolveLink(created.entity_type)}/${created.id}`);
      },
      onError: () => setSubmitting(false),
    });
  };
  return (
    <Dialog
      open
      onClose={onClose}
      title={target === 'Grouping' ? t_i18n('Create a grouping from the cluster') : t_i18n('Create a campaign from the cluster')}
      showCloseButton
    >
      <Formik<PromoteFormValues> initialValues={initialValues} validationSchema={validation} onSubmit={onSubmit}>
        {({ submitForm, isSubmitting, setFieldValue, values }) => (
          <Form>
            <Text variant="content-compact" className="mb-4">
              {target === 'Grouping'
                ? t_i18n('The grouping will contain the cluster members you can access.')
                : t_i18n('The campaign will be related to the cluster members you can access.')}
            </Text>
            <Field component={TextField} name="name" label={t_i18n('Name')} required fullWidth />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              fullWidth
              multiline
              rows="4"
              style={fieldSpacingContainerStyle}
            />
            <CreatedByField name="createdBy" style={fieldSpacingContainerStyle} setFieldValue={setFieldValue} />
            <ObjectMarkingField name="objectMarking" style={fieldSpacingContainerStyle} setFieldValue={setFieldValue} />
            <Box sx={{ mt: 2 }}>
              <Switch
                checked={values.include_features}
                onCheckedChange={(checked) => setFieldValue('include_features', checked)}
                label={t_i18n('Include the shared features (certificates, ASN, registrars...)')}
              />
            </Box>
            <FormButtonContainer>
              <Button variant="secondary" onClick={onClose} disabled={isSubmitting}>
                {t_i18n('Cancel')}
              </Button>
              <Button onClick={submitForm} disabled={isSubmitting} data-testid="graph-cluster-promote-submit">
                {t_i18n('Create')}
              </Button>
            </FormButtonContainer>
          </Form>
        )}
      </Formik>
    </Dialog>
  );
};

export default GraphClusterPromoteDialog;
