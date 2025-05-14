import { truncate } from './String';
import { getFileUri, isEmptyField } from './utils';
import { authorizedMembersToOptions } from './authorizedMembers';

export const convertStatus = (t, element) => ((element?.status?.template?.name ?? null) === null
  ? ''
  : {
    label: element?.status?.template?.name ?? null,
    color: element?.status?.template?.color ?? null,
    value: element?.status?.id ?? null,
    order: element?.status?.order ?? null,
  });

export const convertMarking = (element) => ({
  label: element.definition ?? element.id,
  value: element.id,
  color: element.x_opencti_color,
  definition_type: element.definition_type,
  x_opencti_order: element.x_opencti_order,
  entity: {
    ...element,
  },
});

export const convertMarkings = (element) => (element?.objectMarking ?? []).map((n) => convertMarking(n));

export const convertMarkingsWithoutEdges = (element, field = 'objectMarking') => (element?.[field] ?? []).map((n) => convertMarking(n));

export const convertTriggers = (element) => (element?.triggers ?? []).map((n) => ({
  label: n.name,
  value: n.id,
}));

export const convertAuthorizedMembers = (element) => authorizedMembersToOptions(element?.authorized_members ?? []);

export const convertAssignees = (element) => (element?.objectAssignee ?? []).map((n) => ({
  label: n.name,
  value: n.id,
}));

export const convertParticipants = (element) => (element?.objectParticipant ?? []).map((n) => ({
  label: n.name,
  value: n.id,
}));

export const convertOrganizations = (element) => (element?.objectOrganization?.edges ?? []).map((n) => ({
  label: n.node.name,
  value: n.node.id,
}));

export const convertKillChainPhases = (element) => (element?.killChainPhases ?? []).map((n) => ({
  label: `[${n.kill_chain_name}] ${n.phase_name}`,
  value: n.id,
}));

export const convertExternalReferences = (element) => (element?.externalReferences?.edges ?? []).map((n) => ({
  label: `[${n.node.source_name}] ${truncate(
    n.node.description || n.node.url || n.node.external_id,
    150,
  )}`,
  value: n.node.id,
}));

export const convertImagesToCarousel = (element) => {
  const images = element.images.edges ?? [];
  const carouselImages = images
    ? images.filter(({ node }) => node?.metaData.inCarousel === true)
    : [];
  carouselImages.sort((a, b) => a.node.metaData.order - b.node.metaData.order);
  return carouselImages.map((file) => ({
    tooltipTitle: file.node.metaData.description,
    imageSrc: getFileUri(file.node.id),
    altText: file.node.name,
    id: file.node.id,
  }));
};

export const convertCreatedBy = (element, field = 'createdBy') => (isEmptyField(element?.[field])
  ? ''
  : {
    label: element[field].name,
    value: element[field].id,
    type: element[field].entity_type,
  });

export const convertUser = (element, field = 'user') => (isEmptyField(element?.[field])
  ? ''
  : {
    label: element[field].name,
    value: element[field].id,
    type: element[field].entity_type,
  });

export const convertMapper = (element, field = 'csvMapper') => {
  return (isEmptyField(element?.[field])
    ? ''
    : {
      label: element[field].name,
      value: element[field].id,
    });
};

export const convertNotifiers = (element) => element?.notifiers?.map(({ id, name }) => ({ value: id, label: name }));

export const filterEventTypesOptions = [
  { value: 'create', label: 'Creation' },
  { value: 'update', label: 'Modification' },
  { value: 'delete', label: 'Deletion' },
];

export const instanceEventTypesOptions = [
  { value: 'update', label: 'Modification' },
  { value: 'delete', label: 'Deletion' },
];

export const convertEventTypes = (element) => element?.event_types?.map((event_type) => {
  return filterEventTypesOptions.find((o) => o.value === event_type);
});
