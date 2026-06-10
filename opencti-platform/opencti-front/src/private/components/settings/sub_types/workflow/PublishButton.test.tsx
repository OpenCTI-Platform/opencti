import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ThemeProvider, createTheme, ThemeOptions } from '@mui/material/styles';
import PublishButton from './PublishButton';
import ThemeDark from '../../../../../components/ThemeDark';

// Mock useFormatter
vi.mock('../../../../../components/i18n', () => ({
  default: () => {},
  useFormatter: () => ({
    t_i18n: (key: string) => key,
  }),
}));

// Create a test theme with all required properties
const testTheme = createTheme(ThemeDark() as ThemeOptions);

// Helper to render with theme
const renderWithTheme = (component: React.ReactElement) => {
  return render(
    <ThemeProvider theme={testTheme}>
      {component}
    </ThemeProvider>,
  );
};

describe('PublishButton', () => {
  const mockOnPublish = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Null validation status', () => {
    it('should return null when validationStatus is null', () => {
      const { container } = renderWithTheme(
        <PublishButton validationStatus={null} onPublish={mockOnPublish} />,
      );
      expect(container.firstChild).toBeNull();
    });
  });

  describe('Published state (green)', () => {
    it('should render published button when published and no errors', () => {
      renderWithTheme(
        <PublishButton
          validationStatus={{ published: true, validationErrors: [] }}
          onPublish={mockOnPublish}
        />,
      );

      const button = screen.getByRole('button', { name: /Published/i });
      expect(button).toBeInTheDocument();
      expect(button).toBeDisabled();
    });
  });

  describe('Unpublished with errors (red)', () => {
    const validationErrors = [
      {
        type: 'duplicate_state',
        message: 'State "open" is duplicated',
        path: [{ id: 'state-1', entity_type: 'Status' }],
      },
      {
        type: 'missing_transition',
        message: 'No transitions defined for state "closed"',
        path: null,
      },
    ];

    it('should render disabled button when not published and has errors', () => {
      renderWithTheme(
        <PublishButton
          validationStatus={{ published: false, validationErrors }}
          onPublish={mockOnPublish}
        />,
      );

      const button = screen.getByRole('button', { name: /Publish/i });
      expect(button).toBeInTheDocument();
      expect(button).toBeDisabled();
    });
  });

  describe('Unpublished without errors (orange)', () => {
    it('should render enabled button when not published and no errors', () => {
      renderWithTheme(
        <PublishButton
          validationStatus={{ published: false, validationErrors: [] }}
          onPublish={mockOnPublish}
        />,
      );

      const button = screen.getByRole('button', { name: /Publish/i });
      expect(button).toBeInTheDocument();
      expect(button).not.toBeDisabled();
    });

    it('should call onPublish when button is clicked', async () => {
      const user = userEvent.setup();
      renderWithTheme(
        <PublishButton
          validationStatus={{ published: false, validationErrors: [] }}
          onPublish={mockOnPublish}
        />,
      );

      const button = screen.getByRole('button', { name: /Publish/i });
      await user.click(button);

      expect(mockOnPublish).toHaveBeenCalledTimes(1);
    });
  });
});
