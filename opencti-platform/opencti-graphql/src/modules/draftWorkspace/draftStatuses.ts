export const DRAFT_STATUS_OPEN = 'open';
export const DRAFT_STATUS_VALIDATED = 'validated';

const DRAFT_STATUSES = [DRAFT_STATUS_OPEN, DRAFT_STATUS_VALIDATED];

export const getDraftStatuses = () => {
  return [...DRAFT_STATUSES];
};
