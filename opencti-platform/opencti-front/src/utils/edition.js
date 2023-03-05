import { truncate } from './String';
import { isEmptyField } from './utils';

export const convertStatus = (t, element) => ((element?.status?.template?.name ?? null) === null
  ? ''
  : {
    label: element?.status?.template?.name ?? null,
    color: element?.status?.template?.color ?? null,
    value: element?.status?.id ?? null,
    order: element?.status?.order ?? null,
  });

export const convertMarkings = (element) => (element?.objectMarking?.edges ?? []).map((n) => ({
  label: n.node.definition,
  value: n.node.id,
}));

export const convertTriggers = (element) => (element?.triggers ?? []).map((n) => ({
  label: n.name,
  value: n.id,
}));

export const convertAssignees = (element) => (element?.objectAssignee?.edges ?? []).map((n) => ({
  label: n.node.name,
  value: n.node.id,
}));

export const convertOrganizations = (element) => (element?.objectOrganization?.edges ?? []).map((n) => ({
  label: n.node.name,
  value: n.node.id,
}));

export const convertKillChainPhases = (element) => (element?.killChainPhases?.edges ?? []).map((n) => ({
  label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
  value: n.node.id,
}));

export const convertExternalReferences = (element) => (element?.externalReferences?.edges ?? []).map((n) => ({
  label: `[${n.node.source_name}] ${truncate(
    n.node.description || n.node.url || n.node.external_id,
    150,
  )}`,
  value: n.node.id,
}));

export const convertCreatedBy = (element) => (isEmptyField(element?.createdBy)
  ? ''
  : { label: element.createdBy.name, value: element.createdBy.id });
