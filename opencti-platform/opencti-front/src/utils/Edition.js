import * as R from 'ramda';

export const convertStatus = (t, element) => (R.pathOr(null, ['status', 'template', 'name'], element) === null
  ? ''
  : {
    label: t(
      `status_${R.pathOr(null, ['status', 'template', 'name'], element)}`,
    ),
    color: R.pathOr(null, ['status', 'template', 'color'], element),
    value: R.pathOr(null, ['status', 'id'], element),
    order: R.pathOr(null, ['status', 'order'], element),
  });

export const convertMarkings = (element) => R.pipe(
  R.pathOr([], ['objectMarking', 'edges']),
  R.map((n) => ({
    label: n.node.definition,
    value: n.node.id,
  })),
)(element);

export const convertCreatedBy = (element) => (R.pathOr(null, ['createdBy', 'name'], element) === null
  ? ''
  : {
    label: R.pathOr(null, ['createdBy', 'name'], element),
    value: R.pathOr(null, ['createdBy', 'id'], element),
  });
