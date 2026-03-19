import { describe, it, vi, expect, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import FormView from './FormView';
import testRender from '../../../../../utils/tests/test-render';
import { MockPayloadGenerator } from 'relay-test-utils';
import * as useGrantedModule from '../../../../../utils/hooks/useGranted';

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
    { name: 'name', label: 'Name', type: 'text', attributeMapping: { entity: 'main_entity', attributeName: 'name' } }
  ],
  mainEntityType: 'Report',
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

describe('FormView', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render form and fields', async () => {
    useGrantedSpy.mockReturnValue(true); // Grant all by default

    const { environment } = testRender(<FormView />);

    environment.mock.resolveMostRecentOperation((operation) => {
        return MockPayloadGenerator.generate(operation, {
            Form: () => mockForm,
        });
    });
    
    // In a real scenario we would wait for the form fields to appear
    await waitFor(() => {
        expect(screen.getByText('Test Form')).toBeInTheDocument();
    });
  });

  it('should show Enabled Access Restriction switch disabled if user has no BYPASS', async () => {
    // Mock user having BYPASS = false
    // useGranted is called nicely, so we can mock implementations.
    // In FormView: const isBypass = useGranted([BYPASS]);
    // It also calls useGranted for MODULES and INGESTION.
    
    useGrantedSpy.mockImplementation((capabilities) => {
        if (capabilities.includes(useGrantedModule.BYPASS)) return false;
        return true; 
    });

    const { environment } = testRender(<FormView />);

    environment.mock.resolveMostRecentOperation((operation) => {
        return MockPayloadGenerator.generate(operation, {
            Form: () => mockForm,
        });
    });

    // authorizedMembers field is there
    await waitFor(() => {
        expect(screen.getByText('Authorized Members')).toBeInTheDocument();
    });

    // Find the AuthorizedMembersField component output.
    // It usually renders "Activate access restriction" switch.
    // And expected to be disabled.
    // We might need to inspect the DOM structure or check if input is disabled.
    
    // Wait for the switch to be available
    await waitFor(() => {
        expect(screen.getByLabelText('Activate access restriction')).toBeInTheDocument();
    });
    
    const switchInput = screen.getByLabelText('Activate access restriction');
    expect(switchInput).toBeDisabled();
  });

  it('should show Enabled Access Restriction switch enabled if user HAS BYPASS', async () => {
    
    useGrantedSpy.mockImplementation((capabilities) => {
        if (capabilities.includes(useGrantedModule.BYPASS)) return true;
        return true; 
    });

    const { environment } = testRender(<FormView />);

    environment.mock.resolveMostRecentOperation((operation) => {
        return MockPayloadGenerator.generate(operation, {
            Form: () => mockForm,
        });
    });

    await waitFor(() => {
        expect(screen.getByLabelText('Activate access restriction')).toBeInTheDocument();
    });
    
    const switchInput = screen.getByLabelText('Activate access restriction');
    expect(switchInput).not.toBeDisabled();
  });
});
