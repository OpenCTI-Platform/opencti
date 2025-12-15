import { addInSessionStorageStack, getSessionStorageItem, setSessionStorageItem } from '../../../../../utils/sessionStorage';
import { ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';

interface InvestigationOpExpand {
  type: 'expand';
  dateTime: number;
  objectsIds: string[];
}

interface InvestigationOpAdd {
  type: 'add';
  dateTime: number;
  objectsIds: string[];
}

interface InvestigationOpRemove {
  type: 'remove';
  dateTime: number;
  objects: ObjectToParse[];
}

type AllInvestigationOps = InvestigationOpExpand | InvestigationOpAdd | InvestigationOpRemove;
type InvestigationState = AllInvestigationOps[];

export const useInvestigationState = (investigationId: string) => {
  const STORAGE_KEY = `investigation-state-${investigationId}`;

  const getStackOfInvestigationState = () => {
    return getSessionStorageItem<InvestigationState>(STORAGE_KEY);
  };

  const addInvestigationOpInStack = (operation: AllInvestigationOps) => {
    addInSessionStorageStack<AllInvestigationOps>(STORAGE_KEY, operation, 20);
  };

  const containsExpandOp = () => {
    const state = getStackOfInvestigationState() ?? [];
    return state.some((op) => op.type === 'expand');
  };

  const getLastExpandOp = (): InvestigationOpExpand | null => {
    const state = getStackOfInvestigationState() ?? [];
    while (state.length > 0) {
      const op = state.shift();
      if (op?.type === 'expand') return op;
    }
    return null;
  };

  const getOpsUntilExpand = () => {
    if (!containsExpandOp()) return [];
    const state = getStackOfInvestigationState() ?? [];
    const ops: AllInvestigationOps[] = [];
    let found = false;
    while (!found && state.length > 0) {
      const op = state.shift();
      if (op) {
        ops.push(op);
        if (op.type === 'expand') found = true;
      }
    }
    // Update the stack in session storage.
    if (state.length === 0) {
      sessionStorage.removeItem(STORAGE_KEY);
    } else {
      setSessionStorageItem(STORAGE_KEY, state);
    }
    return ops;
  };

  return {
    getStackOfInvestigationState,
    addInvestigationOpInStack,
    containsExpandOp,
    getOpsUntilExpand,
    getLastExpandOp,
  };
};
