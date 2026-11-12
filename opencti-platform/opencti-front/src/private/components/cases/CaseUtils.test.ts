import { describe, expect, it } from 'vitest';
import { isWorkflowDrivenRequestAccess } from './CaseUtils';
import { StatusScopeEnum } from '../../../utils/statusConstants';

const requestAccessInstance = { scope: StatusScopeEnum.REQUEST_ACCESS };

describe('isWorkflowDrivenRequestAccess', () => {
  it('is true for a request record on a request access instance', () => {
    expect(isWorkflowDrivenRequestAccess({ x_opencti_request_access: JSON.stringify({ status: 'NEW' }), workflowInstance: requestAccessInstance })).toBe(true);
  });

  it('is false without a request record', () => {
    expect(isWorkflowDrivenRequestAccess({ x_opencti_request_access: null, workflowInstance: requestAccessInstance })).toBe(false);
  });

  it('is false for a malformed or scalar request record', () => {
    expect(isWorkflowDrivenRequestAccess({ x_opencti_request_access: 'not json', workflowInstance: requestAccessInstance })).toBe(false);
    expect(isWorkflowDrivenRequestAccess({ x_opencti_request_access: '42', workflowInstance: requestAccessInstance })).toBe(false);
    expect(isWorkflowDrivenRequestAccess({ x_opencti_request_access: 'null', workflowInstance: requestAccessInstance })).toBe(false);
  });

  it('is false on an instance of another scope', () => {
    expect(isWorkflowDrivenRequestAccess({ x_opencti_request_access: JSON.stringify({ status: 'NEW' }), workflowInstance: { scope: 'GLOBAL' } })).toBe(false);
  });
});
