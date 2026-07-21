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
  const mockOnReset = vi.fn();
  const mockOnRestore = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Null validation status', () => {
    it('should return null when validationStatus is null', () => {
      const { container } = renderWithTheme(
        <PublishButton
          validationStatus={null}
          onPublish={mockOnPublish}
          onReset={mockOnReset}
          onRestore={mockOnRestore}
          hasPublishedVersion={true}
        />,
      );
      expect(container.firstChild).toBeNull();
    });
  });

  describe('Published state (green)', () => {
    it('should render published button when published and no errors', () => {
      renderWithTheme(
        <PublishButton
          validationStatus={{ hasUnpublishedChanges: false, validationErrors: [] }}
          onPublish={mockOnPublish}
          onReset={mockOnReset}
          onRestore={mockOnRestore}
          hasPublishedVersion={true}
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

    it('should render enabled button when not published and has errors', () => {
      renderWithTheme(
        <PublishButton
          validationStatus={{ hasUnpublishedChanges: true, validationErrors }}
          onPublish={mockOnPublish}
          onReset={mockOnReset}
          onRestore={mockOnRestore}
          hasPublishedVersion={true}
        />,
      );

      const button = screen.getByRole('button', { name: /Publish/i });
      expect(button).toBeInTheDocument();
      expect(button).not.toBeDisabled();
    });

    it('should call onPublish when button is clicked (to trigger toast)', async () => {
      const user = userEvent.setup();
      renderWithTheme(
        <PublishButton
          validationStatus={{ hasUnpublishedChanges: true, validationErrors }}
          onPublish={mockOnPublish}
          onReset={mockOnReset}
          onRestore={mockOnRestore}
          hasPublishedVersion={true}
        />,
      );

      await user.click(screen.getByRole('button', { name: /Publish/i }));
      expect(mockOnPublish).toHaveBeenCalledTimes(1);
    });
  });

  describe('Unpublished without errors (orange)', () => {
    it('should render enabled button when not published and no errors', () => {
      renderWithTheme(
        <PublishButton
          validationStatus={{ hasUnpublishedChanges: true, validationErrors: [] }}
          onPublish={mockOnPublish}
          onReset={mockOnReset}
          onRestore={mockOnRestore}
          hasPublishedVersion={true}
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
          validationStatus={{ hasUnpublishedChanges: true, validationErrors: [] }}
          onPublish={mockOnPublish}
          onReset={mockOnReset}
          onRestore={mockOnRestore}
          hasPublishedVersion={true}
        />,
      );

      const button = screen.getByRole('button', { name: /Publish/i });
      await user.click(button);

      expect(mockOnPublish).toHaveBeenCalledTimes(1);
    });
  });

  describe('Reset flow', () => {
    it('should open reset confirmation and call onReset when confirmed', async () => {
      const user = userEvent.setup();
      renderWithTheme(
        <PublishButton
          validationStatus={{ hasUnpublishedChanges: true, validationErrors: [] }}
          onPublish={mockOnPublish}
          onReset={mockOnReset}
          onRestore={mockOnRestore}
          hasPublishedVersion={true}
        />,
      );

      await user.click(screen.getByRole('button', { name: /More workflow options/i }));
      await user.click(screen.getByRole('menuitem', { name: /Reset workflow/i }));
      await user.click(screen.getByRole('button', { name: /^Reset$/i }));

      expect(mockOnReset).toHaveBeenCalledTimes(1);
    });
  });

  describe('Restore flow', () => {
    it('should open restore confirmation when "Restore published version" menu item is clicked', async () => {
      const user = userEvent.setup();
      renderWithTheme(
        <PublishButton
          validationStatus={{ hasUnpublishedChanges: true, validationErrors: [] }}
          onPublish={mockOnPublish}
          onReset={mockOnReset}
          onRestore={mockOnRestore}
          hasPublishedVersion={true}
        />,
      );

      await user.click(screen.getByRole('button', { name: /More workflow options/i }));
      await user.click(screen.getByRole('menuitem', { name: /Restore published version/i }));

      expect(screen.getByRole('button', { name: /^Restore$/i })).toBeInTheDocument();
    });

    it('should call onRestore when restore is confirmed', async () => {
      const user = userEvent.setup();
      renderWithTheme(
        <PublishButton
          validationStatus={{ hasUnpublishedChanges: true, validationErrors: [] }}
          onPublish={mockOnPublish}
          onReset={mockOnReset}
          onRestore={mockOnRestore}
          hasPublishedVersion={true}
        />,
      );

      await user.click(screen.getByRole('button', { name: /More workflow options/i }));
      await user.click(screen.getByRole('menuitem', { name: /Restore published version/i }));
      await user.click(screen.getByRole('button', { name: /^Restore$/i }));

      expect(mockOnRestore).toHaveBeenCalledTimes(1);
    });

    it('should not call onRestore when restore is cancelled', async () => {
      const user = userEvent.setup();
      renderWithTheme(
        <PublishButton
          validationStatus={{ hasUnpublishedChanges: true, validationErrors: [] }}
          onPublish={mockOnPublish}
          onReset={mockOnReset}
          onRestore={mockOnRestore}
          hasPublishedVersion={true}
        />,
      );

      await user.click(screen.getByRole('button', { name: /More workflow options/i }));
      await user.click(screen.getByRole('menuitem', { name: /Restore published version/i }));
      await user.click(screen.getByRole('button', { name: /Cancel/i }));

      expect(mockOnRestore).not.toHaveBeenCalled();
    });

    it('should disable "Restore published version" menu item when already published', async () => {
      const user = userEvent.setup();
      renderWithTheme(
        <PublishButton
          validationStatus={{ hasUnpublishedChanges: false, validationErrors: [] }}
          onPublish={mockOnPublish}
          onReset={mockOnReset}
          onRestore={mockOnRestore}
          hasPublishedVersion={true}
        />,
      );

      await user.click(screen.getByRole('button', { name: /More workflow options/i }));
      const restoreItem = screen.getByRole('menuitem', { name: /Restore published version/i });
      expect(restoreItem).toHaveAttribute('aria-disabled', 'true');
    });

    it('should disable "Restore published version" menu item when workflow has never been published', async () => {
      const user = userEvent.setup();
      renderWithTheme(
        <PublishButton
          validationStatus={{ hasUnpublishedChanges: true, validationErrors: [] }}
          onPublish={mockOnPublish}
          onReset={mockOnReset}
          onRestore={mockOnRestore}
          hasPublishedVersion={false}
        />,
      );

      await user.click(screen.getByRole('button', { name: /More workflow options/i }));
      const restoreItem = screen.getByRole('menuitem', { name: /Restore published version/i });
      expect(restoreItem).toHaveAttribute('aria-disabled', 'true');
    });
  });
});
