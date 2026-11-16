export const confirmsOnlyAboveLimit = (actions: readonly { type: string }[]) => actions.length > 0
  && actions.every((action) => action.type === 'ENRICHMENT');
