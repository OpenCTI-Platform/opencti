import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import RequestAccessValidatorGroup from './RequestAccessValidatorGroup';

let mockConfiguration: { approval_admin: { id: string; name: string }[] } | null = null;

vi.mock('react-relay', async () => {
  const actual = await vi.importActual('react-relay');
  return {
    ...actual,
    graphql: vi.fn((query) => query),
    useFragment: vi.fn(() => mockConfiguration),
  };
});

vi.mock('../SubTypeOutletContext', () => ({
  useSubTypeOutletContext: () => ({
    subType: { settings: { requestAccessConfiguration: { id: 'request-access-configuration' } } },
  }),
}));

vi.mock('../../../../../components/i18n', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../../components/i18n')>(),
  useFormatter: () => ({ t_i18n: (key: string) => key }),
}));

const mockCommit = vi.fn();
vi.mock('../../../../../utils/hooks/useApiMutation', () => ({
  default: () => [mockCommit],
}));

// The real field loads the groups through the network: the stub only exposes what the form hands it.
vi.mock('@components/common/form/GroupField', () => ({
  default: ({ label, onChange }: { label: string; onChange: (name: string, value: unknown) => void }) => (
    <div>
      <span>{label}</span>
      <button onClick={() => onChange('approvalAdmin', { label: 'SOC', value: 'group-soc' })}>pick</button>
      <button onClick={() => onChange('approvalAdmin', null)}>clear</button>
    </div>
  ),
}));

describe('RequestAccessValidatorGroup', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConfiguration = { approval_admin: [{ id: 'group-analysts', name: 'Analysts' }] };
  });

  it('labels the field as the validator group', () => {
    render(<RequestAccessValidatorGroup />);

    expect(screen.getByText('Validator group membership:')).toBeInTheDocument();
  });

  it('saves the picked group as the only approval admin, leaving the statuses alone', async () => {
    const user = userEvent.setup();
    render(<RequestAccessValidatorGroup />);

    await user.click(screen.getByText('pick'));

    expect(mockCommit).toHaveBeenCalledWith(
      expect.objectContaining({ variables: { input: { approval_admin: ['group-soc'] } } }),
    );
  });

  it('saves an empty list when the group is cleared', async () => {
    const user = userEvent.setup();
    render(<RequestAccessValidatorGroup />);

    await user.click(screen.getByText('clear'));

    expect(mockCommit).toHaveBeenCalledWith(
      expect.objectContaining({ variables: { input: { approval_admin: [] } } }),
    );
  });
});
