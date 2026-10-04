/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { Suspense, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import type { PayloadError } from 'relay-runtime';
import type { FormikHelpers } from 'formik';
import Grid from '@mui/material/Grid2';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import DialogActions from '@mui/material/DialogActions';
import { AddOutlined, DeleteOutlined, EditOutlined } from '@mui/icons-material';
import { Chip, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Card from '@common/card/Card';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import Drawer from '@components/common/drawer/Drawer';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import PageContainer from '../../../../components/PageContainer';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import InvestigationPolicyForm from './InvestigationPolicyForm';
import {
  AUTONOMOUS_ACTION_LABELS,
  type InvestigationPolicyFormPolicy,
  type InvestigationPolicyFormValues,
  NEW_POLICY,
  toPolicyEditInputs,
  toPolicyInput,
} from './investigationPolicyUtils';
import { DEFAULT_PACK, formatProbability, reportMutationOutcome } from '../../investigation_runs/investigationRunUtils';
import { InvestigationPoliciesQuery, InvestigationPoliciesQuery$data } from './__generated__/InvestigationPoliciesQuery.graphql';
import { InvestigationPoliciesAddMutation } from './__generated__/InvestigationPoliciesAddMutation.graphql';
import { InvestigationPoliciesEditMutation } from './__generated__/InvestigationPoliciesEditMutation.graphql';
import { InvestigationPoliciesDeleteMutation } from './__generated__/InvestigationPoliciesDeleteMutation.graphql';

const investigationPoliciesQuery = graphql`
  query InvestigationPoliciesQuery {
    investigationPolicies(first: 100, orderBy: name, orderMode: asc) {
      edges {
        node {
          id
          name
          description
          is_default
          pack_id
          pack_options
          agent_slug
          allowed_actions
          enrichment_connector_ids
          approval_connector_ids
          auto_approve_low_risk
          auto_approve_min_confidence
          attribution_min_confidence
          max_iterations
          max_enrichment_jobs
          max_minutes
          trigger_on_case_rfi_creation
          runAs {
            id
            name
          }
          runs_count
          acceptance {
            hypotheses_accepted
            hypotheses_rejected
            recommendations_accepted
            recommendations_rejected
            rate
          }
        }
      }
    }
    investigationEnrichmentConnectors {
      id
      name
    }
    investigationPacks {
      packs {
        slug
        label
      }
    }
  }
`;

const investigationPoliciesAddMutation = graphql`
  mutation InvestigationPoliciesAddMutation($input: InvestigationPolicyAddInput!) {
    investigationPolicyAdd(input: $input) {
      id
    }
  }
`;

const investigationPoliciesEditMutation = graphql`
  mutation InvestigationPoliciesEditMutation($id: ID!, $input: [EditInput!]!) {
    investigationPolicyFieldPatch(id: $id, input: $input) {
      id
      name
      description
      is_default
      pack_id
      pack_options
      agent_slug
      allowed_actions
      enrichment_connector_ids
      approval_connector_ids
      auto_approve_low_risk
      auto_approve_min_confidence
      attribution_min_confidence
      max_iterations
      max_enrichment_jobs
      max_minutes
      trigger_on_case_rfi_creation
      runAs {
        id
        name
      }
    }
  }
`;

const investigationPoliciesDeleteMutation = graphql`
  mutation InvestigationPoliciesDeleteMutation($id: ID!) {
    investigationPolicyDelete(id: $id)
  }
`;

type Policy = NonNullable<NonNullable<InvestigationPoliciesQuery$data['investigationPolicies']>['edges'][number]>['node'];

interface PolicyCardProps {
  policy: Policy;
  connectorNames: Map<string, string>;
  packLabels: Map<string, string>;
  onEdit: () => void;
  onDelete: () => void;
}

// A count of connectors, with their names in a tooltip.
const ConnectorCount = ({ ids, names, empty }: { ids: readonly string[]; names: Map<string, string>; empty: string }) => {
  const { t_i18n } = useFormatter();
  if (ids.length === 0) return <>{empty}</>;
  const listed = ids.map((id) => names.get(id)).filter((name): name is string => !!name);
  const label = t_i18n('{count, plural, one {# connector} other {# connectors}}', { values: { count: ids.length } });
  if (listed.length === 0) return <>{label}</>;
  return (
    <Tooltip>
      <TooltipTrigger asChild><span tabIndex={0}>{label}</span></TooltipTrigger>
      <TooltipContent>{listed.join(', ')}</TooltipContent>
    </Tooltip>
  );
};

const PolicyCard = ({ policy, connectorNames, packLabels, onEdit, onDelete }: PolicyCardProps) => {
  const { t_i18n } = useFormatter();
  const decisions = policy.acceptance.hypotheses_accepted + policy.acceptance.hypotheses_rejected
    + policy.acceptance.recommendations_accepted + policy.acceptance.recommendations_rejected;
  const packLabel = !policy.pack_id || policy.pack_id === DEFAULT_PACK
    ? t_i18n('OpenCTI case investigation')
    : (packLabels.get(policy.pack_id) ?? t_i18n('Custom pack'));
  const facts: [string, React.ReactNode][] = [
    [t_i18n('Investigations'), String(policy.runs_count)],
    [t_i18n('Analyst acceptance'), decisions > 0 && policy.acceptance.rate !== null && policy.acceptance.rate !== undefined ? formatProbability(policy.acceptance.rate) : t_i18n('No decision yet')],
    [t_i18n('Budget'), t_i18n('{iterations} iterations - {jobs} enrichment jobs - {minutes} min', {
      values: { iterations: policy.max_iterations, jobs: policy.max_enrichment_jobs, minutes: policy.max_minutes },
    })],
    [t_i18n('Minimum confidence to write an attribution'), `${policy.attribution_min_confidence}%`],
    [t_i18n('Enrichment connectors'), <ConnectorCount key="enrichment" ids={policy.enrichment_connector_ids} names={connectorNames} empty={t_i18n('All enrichment connectors')} />],
    [t_i18n('Connectors that need an approval'), <ConnectorCount key="approval" ids={policy.approval_connector_ids} names={connectorNames} empty={t_i18n('None')} />],
    [t_i18n('Investigation pack'), packLabel],
    [t_i18n('Run automatic investigations as'), policy.runAs?.name ?? t_i18n('Platform administrator')],
  ];
  return (
    <Card
      title={policy.name}
      action={(
        <Stack direction="row" spacing={0.5}>
          <IconButton size="small" variant="tertiary" aria-label={t_i18n('Edit the policy {name}', { values: { name: policy.name } })} onClick={onEdit}>
            <EditOutlined fontSize="small" />
          </IconButton>
          {!policy.is_default && (
            <IconButton size="small" variant="tertiary" aria-label={t_i18n('Delete the policy {name}', { values: { name: policy.name } })} onClick={onDelete}>
              <DeleteOutlined fontSize="small" />
            </IconButton>
          )}
        </Stack>
      )}
    >
      <Stack spacing={1.5}>
        <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
          {policy.is_default && <Chip label={t_i18n('Default policy')} severity="info" size="sm" />}
          {policy.auto_approve_low_risk && <Chip label={t_i18n('Low-risk drafts approved automatically')} severity="medium" size="sm" />}
          {policy.trigger_on_case_rfi_creation && <Chip label={t_i18n('Investigates new requests for information')} size="sm" />}
        </Stack>
        {policy.description && <Typography variant="body2" color="text.secondary">{policy.description}</Typography>}
        {facts.map(([label, value]) => (
          <Stack key={label} direction="row" justifyContent="space-between" spacing={2}>
            <Typography variant="body2" color="text.secondary">{label}</Typography>
            <Typography variant="body2" sx={{ textAlign: 'right' }}>{value}</Typography>
          </Stack>
        ))}
        <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
          {policy.allowed_actions.map((action) => <Chip key={action} label={t_i18n(AUTONOMOUS_ACTION_LABELS[action] ?? action)} size="sm" />)}
        </Stack>
      </Stack>
    </Card>
  );
};

const InvestigationPoliciesContent = () => {
  const { t_i18n } = useFormatter();
  const [fetchKey, setFetchKey] = useState(0);
  const [editing, setEditing] = useState<{ id: string | null; policy: InvestigationPolicyFormPolicy } | null>(null);
  const [deleting, setDeleting] = useState<Policy | null>(null);
  const data = useLazyLoadQuery<InvestigationPoliciesQuery>(investigationPoliciesQuery, {}, { fetchPolicy: 'store-and-network', fetchKey });
  const policies = (data.investigationPolicies?.edges ?? []).map((edge) => edge.node);
  const connectorNames = new Map(data.investigationEnrichmentConnectors.map((connector) => [connector.id, connector.name]));
  const packLabels = new Map((data.investigationPacks?.packs ?? []).map((pack) => [pack.slug, pack.label]));
  const [commitAdd] = useApiMutation<InvestigationPoliciesAddMutation>(investigationPoliciesAddMutation);
  const [commitEdit] = useApiMutation<InvestigationPoliciesEditMutation>(investigationPoliciesEditMutation);
  const [commitDelete, deleteInFlight] = useApiMutation<InvestigationPoliciesDeleteMutation>(investigationPoliciesDeleteMutation);
  const refresh = () => setFetchKey((key) => key + 1);
  const onSubmit = (values: InvestigationPolicyFormValues, { setSubmitting, setErrors }: FormikHelpers<InvestigationPolicyFormValues>) => {
    if (!editing) return;
    const close = () => {
      setSubmitting(false);
      setEditing(null);
      refresh();
    };
    // A rejected mutation keeps the drawer open with what was typed.
    const completeWith = (successMessage: string) => (_: unknown, errors: readonly PayloadError[] | null) => {
      if (reportMutationOutcome(errors, successMessage)) {
        close();
      } else {
        setSubmitting(false);
      }
    };
    const fail = (error: Error) => {
      handleErrorInForm(error, setErrors);
      setSubmitting(false);
    };
    if (editing.id) {
      const input = toPolicyEditInputs(editing.policy, values);
      if (input.length === 0) {
        close();
        return;
      }
      commitEdit({ variables: { id: editing.id, input }, onCompleted: completeWith(t_i18n('The policy was updated')), onError: fail });
    } else {
      commitAdd({ variables: { input: toPolicyInput(values) }, onCompleted: completeWith(t_i18n('The policy was created')), onError: fail });
    }
  };
  return (
    <>
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Typography variant="body2" color="text.secondary">
          {t_i18n('Investigation policies set what Case Autopilot may do on its own, which connectors it may use and how much it may spend. Every investigation follows one policy.')}
        </Typography>
        <Button startIcon={<AddOutlined fontSize="small" />} onClick={() => setEditing({ id: null, policy: NEW_POLICY })} data-testid="investigation-policy-create">
          {t_i18n('Create a policy')}
        </Button>
      </Stack>
      <Grid container spacing={3}>
        {policies.map((policy) => (
          <Grid key={policy.id} size={{ xs: 12, md: 6, xl: 4 }} data-testid="investigation-policy-card">
            <PolicyCard
              policy={policy}
              connectorNames={connectorNames}
              packLabels={packLabels}
              onEdit={() => setEditing({ id: policy.id, policy })}
              onDelete={() => setDeleting(policy)}
            />
          </Grid>
        ))}
      </Grid>
      <Drawer
        title={editing?.id ? t_i18n('Update the policy') : t_i18n('Create a policy')}
        open={!!editing}
        onClose={() => setEditing(null)}
      >
        {editing ? (
          <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <InvestigationPolicyForm
              policy={editing.policy}
              submitLabel={editing.id ? t_i18n('Update') : t_i18n('Create')}
              onSubmit={onSubmit}
              onCancel={() => setEditing(null)}
            />
          </Suspense>
        ) : null}
      </Drawer>
      <Dialog open={!!deleting} onClose={() => setDeleting(null)} title={t_i18n('Delete the policy')} size="small">
        <span>{t_i18n('Investigations already run with this policy are kept. New investigations use the default policy.')}</span>
        <DialogActions>
          <Button variant="secondary" onClick={() => setDeleting(null)} disabled={deleteInFlight}>{t_i18n('Cancel')}</Button>
          <Button
            intent="destructive"
            disabled={deleteInFlight}
            onClick={() => deleting && commitDelete({
              variables: { id: deleting.id },
              onCompleted: (_, errors) => {
                // A policy that investigations in progress depend on is refused: the dialog stays open.
                if (!reportMutationOutcome(errors, t_i18n('The policy was deleted'))) return;
                setDeleting(null);
                refresh();
              },
            })}
          >
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

/** Settings > Customization > Investigation policies. */
const InvestigationPolicies = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Investigation policies | Customization | Settings'));
  const isEnterpriseEdition = useEnterpriseEdition();
  return (
    <div data-testid="investigation-policies-page">
      <PageContainer withGap withRightMenu>
        <Breadcrumbs
          noMargin
          elements={[
            { label: t_i18n('Settings') },
            { label: t_i18n('Customization') },
            { label: t_i18n('Investigation policies'), current: true },
          ]}
        />
        {!isEnterpriseEdition ? (
          <EnterpriseEdition feature="Case Autopilot" />
        ) : (
          <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <InvestigationPoliciesContent />
          </Suspense>
        )}
      </PageContainer>
    </div>
  );
};

export default InvestigationPolicies;
