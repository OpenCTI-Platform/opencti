import React, { Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useNavigate } from 'react-router';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { Switch, Text } from '@filigran/design-system';
import { Box, Skeleton } from '@mui/material';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import ItemIcon from '../../../../components/ItemIcon';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useEntityTranslation from '../../../../utils/hooks/useEntityTranslation';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/markdownField/MarkdownField';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle, type FieldOption } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { resolveLink } from '../../../../utils/Entity';
import { MESSAGING$ } from '../../../../relay/environment';
import { reportPayloadErrors } from '../../common/graph_analytics/graphAnalyticsUtils';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import type { GraphClusterPromoteDialogMutation, GraphClusterPromotionTarget } from './__generated__/GraphClusterPromoteDialogMutation.graphql';
import type { GraphClusterPromoteDialogMembersQuery } from './__generated__/GraphClusterPromoteDialogMembersQuery.graphql';

const PREVIEW_MEMBERS = 5;
const PREVIEW_MEMBERS_ALL = 50;

const membersPreviewQuery = graphql`
  query GraphClusterPromoteDialogMembersQuery($id: String!, $first: Int) {
    graphCluster(id: $id) {
      id
      members(first: $first) {
        edges {
          node {
            id
            entity_type
            representative {
              main
            }
          }
        }
      }
    }
  }
`;

interface MembersPreviewProps {
  queryRef: PreloadedQuery<GraphClusterPromoteDialogMembersQuery>;
  membersCount: number;
  showAll: boolean;
  onShowAll: () => void;
}

/** The members the promotion writes, so the analyst approves what will change. */
const MembersPreview = ({ queryRef, membersCount, showAll, onShowAll }: MembersPreviewProps) => {
  const { t_i18n } = useFormatter();
  const { translateEntityType } = useEntityTranslation();
  const { graphCluster } = usePreloadedQuery(membersPreviewQuery, queryRef);
  const members = (graphCluster?.members?.edges ?? []).map((edge) => edge.node);
  const hidden = Math.max(0, membersCount - members.length);
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }} data-testid="graph-cluster-promote-preview">
      <Box component="ul" sx={{ listStyle: 'none', m: 0, p: 0, display: 'flex', flexDirection: 'column', gap: 0.5 }}>
        {members.map((member) => (
          <Box component="li" key={member.id} sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 0 }}>
            <ItemIcon type={member.entity_type} size="small" />
            <Text variant="content-compact-medium" as="span">{member.representative.main}</Text>
            <Text variant="content-caption" as="span">{translateEntityType(member.entity_type)}</Text>
          </Box>
        ))}
      </Box>
      {hidden > 0 && (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Text variant="content-caption" as="span">
            {t_i18n('and {count, plural, one {# more entity} other {# more entities}}', { values: { count: hidden } })}
          </Text>
          {!showAll && (
            <Button variant="tertiary" size="small" onClick={onShowAll}>
              {t_i18n('Show all')}
            </Button>
          )}
        </Box>
      )}
    </Box>
  );
};

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
  membersCount: number;
  target: GraphClusterPromotionTarget;
  onClose: () => void;
}

/**
 * Explicit analyst action turning a computed cluster into knowledge: a Grouping containing the members (and optionally
 * the shared features), or a Campaign related to them. Only the members the analyst can access are used.
 */
const GraphClusterPromoteDialog = ({ clusterId, clusterName, membersCount, target, onClose }: GraphClusterPromoteDialogProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [commit] = useApiMutation<GraphClusterPromoteDialogMutation>(promoteMutation);
  const [showAll, setShowAll] = useState(false);
  const previewQueryRef = useQueryLoading<GraphClusterPromoteDialogMembersQuery>(
    membersPreviewQuery,
    { id: clusterId, first: showAll ? PREVIEW_MEMBERS_ALL : PREVIEW_MEMBERS },
  );
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
      onCompleted: (response, errors) => {
        setSubmitting(false);
        const created = response.graphClusterPromote;
        if (reportPayloadErrors(errors) || !created) return;
        MESSAGING$.notifySuccess(target === 'Grouping' ? t_i18n('Grouping created from the cluster') : t_i18n('Campaign created from the cluster'));
        onClose();
        navigate(`${resolveLink(created.entity_type)}/${created.id}`);
      },
      onError: () => setSubmitting(false),
    });
  };
  return (
    <Dialog
      open
      onClose={onClose}
      title={target === 'Grouping'
        ? t_i18n('Create a grouping of {count, plural, one {# entity} other {# entities}}', { values: { count: membersCount } })
        : t_i18n('Create a campaign related to {count, plural, one {# entity} other {# entities}}', { values: { count: membersCount } })}
      showCloseButton
    >
      <Formik<PromoteFormValues> initialValues={initialValues} validationSchema={validation} onSubmit={onSubmit}>
        {({ submitForm, isSubmitting, setFieldValue, values }) => (
          <Form>
            <Text variant="content-compact">
              {target === 'Grouping'
                ? t_i18n('The grouping will contain the cluster members you can access.')
                : t_i18n('The campaign will be related to the cluster members you can access.')}
            </Text>
            <Box sx={{ my: 2 }}>
              {previewQueryRef ? (
                <Suspense fallback={<Skeleton variant="rounded" height={120} />}>
                  <MembersPreview queryRef={previewQueryRef} membersCount={membersCount} showAll={showAll} onShowAll={() => setShowAll(true)} />
                </Suspense>
              ) : <Skeleton variant="rounded" height={120} />}
            </Box>
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
                {target === 'Grouping' ? t_i18n('Create the grouping') : t_i18n('Create the campaign')}
              </Button>
            </FormButtonContainer>
          </Form>
        )}
      </Formik>
    </Dialog>
  );
};

export default GraphClusterPromoteDialog;
