import { describe, expect, it } from 'vitest';
import { hasRequestAccessWorkflowConfig } from './hasRequestAccessWorkflowConfig';

const makeSubType = (availableSettings: string[], requestAccessConfiguration: unknown = { id: 'request-access-configuration-id' }) => ({
  settings: { availableSettings, requestAccessConfiguration },
});

describe('hasRequestAccessWorkflowConfig', () => {
  it('is true when EE is active, availableSettings includes request_access_workflow, and configuration is set', () => {
    expect(hasRequestAccessWorkflowConfig(makeSubType(['workflow_configuration', 'request_access_workflow']), true)).toBe(true);
  });

  it('is false when not enterprise edition, even if otherwise configured', () => {
    expect(hasRequestAccessWorkflowConfig(makeSubType(['workflow_configuration', 'request_access_workflow']), false)).toBe(false);
  });

  it('is false when availableSettings does not include request_access_workflow', () => {
    expect(hasRequestAccessWorkflowConfig(makeSubType(['workflow_configuration']), true)).toBe(false);
  });

  it('is false when requestAccessConfiguration is missing', () => {
    expect(hasRequestAccessWorkflowConfig(makeSubType(['workflow_configuration', 'request_access_workflow'], null), true)).toBe(false);
  });
});
