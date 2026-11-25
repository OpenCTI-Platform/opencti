import { useCallback, useContext, useMemo, useState } from 'react';
import { useFormatter } from '../../../../../components/i18n';
import { UserContext } from '../../../../../utils/hooks/useAuth';
import { useExportTheme } from '../../../../../utils/ExportThemeContext';
import { exportImage as exportElementImage } from '../../../../../utils/Image';
import { MESSAGING$ } from '../../../../../relay/environment';
import type { GraphToolbarOption } from '../../../../../components/graph/components/useGraphToolbarActions';
import prepareMatrixCapture from './prepareMatrixCapture';

// Lets the page re-render with the export theme before the capture, as the export buttons do.
const RENDER_DELAY = 1000;

const wait = (delay: number) => new Promise<void>((resolve) => {
  setTimeout(resolve, delay);
});

export interface MatrixImageExport {
  /** One option per theme, with and without background: key `<themeId>:bg` / `<themeId>:nobg`. */
  options: GraphToolbarOption[];
  exporting: boolean;
  exportImage: (optionKey: string) => Promise<void>;
}

/** Image export of the matrix element, one option per theme and background, for the matrix toolbar. */
export const useMatrixImageExport = ({ elementId, name }: { elementId: string; name: string }): MatrixImageExport => {
  const { t_i18n } = useFormatter();
  const { themes } = useContext(UserContext);
  const { setExportTheme } = useExportTheme();
  const [exporting, setExporting] = useState(false);
  const themeNodes = useMemo(() => (themes?.edges ?? []).map(({ node }) => node), [themes]);

  const options = useMemo(() => themeNodes.flatMap((node) => [
    { key: `${node.id}:bg`, label: `${node.name} ${t_i18n('(with background)')}` },
    { key: `${node.id}:nobg`, label: `${node.name} ${t_i18n('(without background)')}` },
  ]), [themeNodes, t_i18n]);

  const exportImage = useCallback(async (optionKey: string) => {
    const [themeId, background] = optionKey.split(':');
    const themeNode = themeNodes.find((node) => node.id === themeId);
    if (!themeNode) return;

    let undoPrepareCapture: (() => void) | null = null;
    try {
      setExporting(true);
      setExportTheme(themeNode);
      await wait(RENDER_DELAY);

      // The user left the matrix view during the wait: nothing to capture, and nothing went wrong.
      const container = document.getElementById(elementId);
      if (!container) return;
      const { offsetWidth, offsetHeight } = container;
      undoPrepareCapture = prepareMatrixCapture(container);

      await exportElementImage(
        elementId,
        offsetWidth,
        offsetHeight,
        name,
        background === 'bg' ? themeNode.theme_background : null,
      );
    } catch {
      MESSAGING$.notifyError(t_i18n('Dashboard cannot be exported to image'));
    } finally {
      undoPrepareCapture?.();
      setExportTheme(null);
      setExporting(false);
    }
  }, [themeNodes, elementId, name, setExportTheme, t_i18n]);

  return { options, exporting, exportImage };
};
