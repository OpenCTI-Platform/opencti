import * as R from 'ramda';

// -- CONVERTOR --

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

export const convertOrganizations = (element) => R.pipe(
  R.pathOr([], ['objectOrganization', 'edges']),
  R.map((n) => ({
    label: n.node.name,
    value: n.node.id,
  })),
)(element);

export const convertCreatedBy = (element) => (R.pathOr(null, ['createdBy', 'name'], element) === null
  ? undefined
  : {
    label: element?.createdBy?.name ?? null,
    value: element?.createdBy?.id ?? null,
  });

// -- EXTRACTOR --

export const handleChangesObjectMarking = (element, values) => {
  const currentMarkingDefinitions = convertMarkings(element);
  const added = values
    .filter(
      (v) => !currentMarkingDefinitions.map((c) => c.value).includes(v.value),
    )
    .at(0);
  const removed = currentMarkingDefinitions
    .filter((c) => !values.map((v) => v.value).includes(c.value))
    .at(0);
  return { added, removed };
};
