import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import { exportImage, exportPdf } from '../utils/Image';
import { MESSAGING$ } from '../relay/environment';
import { ExportButtons } from './ExportButtons';

// Mock the Image utils
vi.mock('../utils/Image', () => ({
  exportImage: vi.fn(),
  exportPdf: vi.fn(),
}));

// Mock MESSAGING$ so we can assert error notifications
vi.mock('../relay/environment', () => ({
  MESSAGING$: { notifyError: vi.fn() },
  environment: {},
}));

// Minimal ExportThemeContext mock
const mockSetExportTheme = vi.fn();
vi.mock('../utils/ExportThemeContext', () => ({
  useExportTheme: () => ({ setExportTheme: mockSetExportTheme }),
}));

const mockThemeNode = {
  id: 'theme-1',
  name: 'Dark',
  theme_background: '#000000',
};

// Minimal props factory
const makeProps = (overrides = {}) => ({
  domElementId: 'test-container',
  name: 'test-export',
  pixelRatio: 1,
  t: (key: string) => key,
  ...overrides,
});

function createExportButtonsInstance(props: Record<string, unknown>) {
  const instance = new ExportButtons({ setExportTheme: mockSetExportTheme, ...props });
  instance.state = { anchorElImage: null, anchorElPdf: null, exporting: false };
  instance.setState = (patch) => Object.assign(instance.state, typeof patch === 'function' ? patch(instance.state) : patch);
  return instance;
}

describe('ExportButtons — exportImage()', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // Create a fake DOM element for the export target
    const container = document.createElement('div');
    container.id = 'test-container';
    document.body.appendChild(container);

    const exportButtonsEl = document.createElement('div');
    exportButtonsEl.id = 'export-buttons';
    document.body.appendChild(exportButtonsEl);
  });

  afterEach(() => {
    document.getElementById('test-container')?.remove();
    document.getElementById('export-buttons')?.remove();
  });

  // ✅ Happy path
  it('calls setExportTheme(themeNode) before export, then setExportTheme(null) in finally', async () => {
    vi.mocked(exportImage).mockResolvedValueOnce(undefined);

    const instance = createExportButtonsInstance(makeProps());
    await instance.exportImage({ domElementId: 'test-container', name: 'test', themeNode: mockThemeNode, background: true });

    // Theme was set to the selected theme before export
    expect(mockSetExportTheme).toHaveBeenNthCalledWith(1, mockThemeNode);
    // Theme was reset to null in finally
    expect(mockSetExportTheme).toHaveBeenNthCalledWith(2, null);
  });

  // 🔴 Error path — the core fix being tested
  it('resets theme to null in finally even when exportImage() throws', async () => {
    vi.mocked(exportImage).mockRejectedValueOnce(new Error('canvas error'));

    const instance = createExportButtonsInstance(makeProps());
    await instance.exportImage({ domElementId: 'test-container', name: 'test', themeNode: mockThemeNode, background: true });

    // setExportTheme(null) MUST still be called despite the error
    expect(mockSetExportTheme).toHaveBeenCalledWith(null);
    expect(MESSAGING$.notifyError).toHaveBeenCalledWith('Dashboard cannot be exported to image');
  });

  // 🔴 Error path — early failure (e.g. DOM element missing)
  it('resets theme to null in finally when domElementId does not exist', async () => {
    const instance = createExportButtonsInstance(makeProps());
    // Pass a non-existent element ID
    await instance.exportImage({ domElementId: 'non-existent-id', name: 'test', themeNode: mockThemeNode, background: true });

    // Theme must still be reset
    expect(mockSetExportTheme).toHaveBeenCalledWith(null);
  });

  it('sets exporting state to false in finally even on error', async () => {
    vi.mocked(exportImage).mockRejectedValueOnce(new Error('fail'));

    const instance = createExportButtonsInstance(makeProps());
    await instance.exportImage({ domElementId: 'test-container', name: 'test', themeNode: mockThemeNode, background: false });

    expect(instance.state.exporting).toBe(false);
  });

  it('passes null background color when background=false', async () => {
    vi.mocked(exportImage).mockResolvedValueOnce(undefined);

    const instance = createExportButtonsInstance(makeProps());
    await instance.exportImage({ domElementId: 'test-container', name: 'test', themeNode: mockThemeNode, background: false });

    expect(exportImage).toHaveBeenCalledWith(
      'test-container',
      expect.any(Number),
      expect.any(Number),
      'test',
      null, // <-- background=false → null color
      1,
      undefined,
    );
  });

  it('passes theme_background when background=true', async () => {
    vi.mocked(exportImage).mockResolvedValueOnce(undefined);

    const instance = createExportButtonsInstance(makeProps());
    await instance.exportImage({ domElementId: 'test-container', name: 'test', themeNode: mockThemeNode, background: true });

    expect(exportImage).toHaveBeenCalledWith(
      'test-container',
      expect.any(Number),
      expect.any(Number),
      'test',
      '#000000', // <-- theme_background
      1,
      undefined,
    );
  });
});

describe('ExportButtons — exportPdf()', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    const container = document.createElement('div');
    container.id = 'test-container';
    document.body.appendChild(container);

    const exportButtonsEl = document.createElement('div');
    exportButtonsEl.id = 'export-buttons';
    document.body.appendChild(exportButtonsEl);
  });

  afterEach(() => {
    document.getElementById('test-container')?.remove();
    document.getElementById('export-buttons')?.remove();
  });

  // ✅ Happy path
  it('calls setExportTheme(themeNode) before export, then setExportTheme(null) in finally', async () => {
    vi.mocked(exportPdf).mockResolvedValueOnce(undefined);

    const instance = createExportButtonsInstance(makeProps());
    await instance.exportPdf({ domElementId: 'test-container', name: 'test', themeNode: mockThemeNode, background: true });

    expect(mockSetExportTheme).toHaveBeenNthCalledWith(1, mockThemeNode);
    expect(mockSetExportTheme).toHaveBeenNthCalledWith(2, null);
  });

  // 🔴 Error path — the core fix being tested
  it('resets theme to null in finally even when exportPdf() throws', async () => {
    vi.mocked(exportPdf).mockRejectedValueOnce(new Error('pdf generation error'));

    const instance = createExportButtonsInstance(makeProps());
    await instance.exportPdf({ domElementId: 'test-container', name: 'test', themeNode: mockThemeNode, background: true });

    expect(mockSetExportTheme).toHaveBeenCalledWith(null);
    expect(MESSAGING$.notifyError).toHaveBeenCalledWith('Dashboard cannot be exported to pdf');
  });

  it('sets exporting state to false in finally even on error', async () => {
    vi.mocked(exportPdf).mockRejectedValueOnce(new Error('fail'));

    const instance = createExportButtonsInstance(makeProps());
    await instance.exportPdf({ domElementId: 'test-container', name: 'test', themeNode: mockThemeNode, background: true });

    expect(instance.state.exporting).toBe(false);
  });

  it('restores export-buttons visibility in finally even on error', async () => {
    vi.mocked(exportPdf).mockRejectedValueOnce(new Error('fail'));

    const instance = createExportButtonsInstance(makeProps());
    await instance.exportPdf({ domElementId: 'test-container', name: 'test', themeNode: mockThemeNode, background: true });

    const buttons = document.getElementById('export-buttons');
    expect(buttons?.getAttribute('style')).toContain('display: block');
  });
});
