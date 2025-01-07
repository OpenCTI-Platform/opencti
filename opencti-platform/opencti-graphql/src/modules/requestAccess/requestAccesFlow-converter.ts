import { buildStixObject } from '../../database/stix-converter';
import type { StixRequestAccessFlow, StoreEntityRequestAccessFlow } from './requestAccessFlow-types';

const convertRequestAccessFlowToStix = (instance: StoreEntityRequestAccessFlow): StixRequestAccessFlow => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    from: instance.from,
    to: instance.to,
    rfi_workflow_id: instance.rfi_workflow_id,
  };
};

export default convertRequestAccessFlowToStix;
