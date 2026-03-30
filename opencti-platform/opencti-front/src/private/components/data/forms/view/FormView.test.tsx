import { describe, it, vi, expect, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import FormView from './FormView';
import testRender, { createMockUserContext } from '../../../../../utils/tests/test-render';
import { MockPayloadGenerator } from 'relay-test-utils';
import * as useGrantedModule from '../../../../../utils/hooks/useGranted';

vi.mock('../../../common/form/AuthorizedMembersField', () => ({
  __esModule: true,
  default: (props: { disabled?: boolean }) => (
    <div data-testid="authorized-members-disabled">{String(!!props.disabled)}</div>
  ),
}));

// Mock useParams
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useParams: () => ({ formId: 'form-id' }),
    useNavigate: () => vi.fn(),
  };
});

// Mock useGranted
const useGrantedSpy = vi.spyOn(useGrantedModule, 'default');

const formSchema = {
  fields: [
    { name: 'name', label: 'Name', type: 'text', attributeMapping: { entity: 'main_entity', attributeName: 'name' } },
  ],
  mainEntityType: 'Report',
  isDraftByDefault: true,
  draftDefaults: {
    author: { type: 'current_user', isEditable: false },
    authorizedMembers: { enabled: true, defaults: [] },
  },
};

const mockForm = {
  id: 'form-id',
  name: 'Test Form',
  description: 'Test Description',
  active: true,
  form_schema: JSON.stringify(formSchema),
};

const mockUserContext = createMockUserContext({ entitySettings: { edges: [] } });

describe('FormView', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render form and fields', async () => {
    useGrantedSpy.mockReturnValue(true); // Grant all by default

    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });

    await waitFor(() => {
      relayEnv.mock.resolveMostRecentOperation((operation: any) => MockPayloadGenerator.generate(operation, { Form: () => mockForm }));
    });

    await waitFor(() => {
        expect(screen.getAllByText('Test Form').length).toBeGreaterThan(0);
    });
  });

  it('should render form without BYPASS capability', async () => {
    useGrantedSpy.mockImplementation((capabilities: string[]) => {
      if (capabilities.includes(useGrantedModule.BYPASS)) return false;
      return true;
    });

    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });

    await waitFor(() => {
      relayEnv.mock.resolveMostRecentOperation((operation: any) => MockPayloadGenerator.generate(operation, { Form: () => mockForm }));
    });

    await waitFor(() => {
      expect(screen.getAllByText('Test Form').length).toBeGreaterThan(0);
    });

    expect(screen.getByTestId('authorized-members-disabled')).toHaveTextContent('true');
  });

  it('should render form with BYPASS capability', async () => {
    useGrantedSpy.mockImplementation((capabilities: string[]) => {
      if (capabilities.includes(useGrantedModule.BYPASS)) return true;
      return true;
    });

    const { relayEnv } = testRender(<FormView />, { userContext: mockUserContext });

    await waitFor(() => {
      relayEnv.mock.resolveMostRecentOperation((operation: any) => MockPayloadGenerator.generate(operation, { Form: () => mockForm }));
    });

    await waitFor(() => {
      expect(screen.getAllByText('Test Form').length).toBeGreaterThan(0);
    });

    expect(screen.getByTestId('authorized-members-disabled')).toHaveTextContent('false');
  });
});
