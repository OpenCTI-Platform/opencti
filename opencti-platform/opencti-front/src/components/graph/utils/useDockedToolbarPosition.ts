import type { CSSProperties } from 'react';
import { OPEN_BAR_WIDTH, SMALL_BAR_WIDTH } from '@components/nav/navBarConstants';
import useAuth from '../../../utils/hooks/useAuth';
import useDraftContext, { DRAFT_TOOLBAR_HEIGHT } from '../../../utils/hooks/useDraftContext';
import useNavOpen from '../../../utils/hooks/useNavOpen';

/**
 * Position of a toolbar docked to the bottom of the window.
 * - Left edge: where the navigation ends. In full screen the view covers the navigation, so 0.
 * - Right edge: where the chatbot sidebar starts.
 * - Bottom: above the draft toolbar and the platform banner, when they are shown.
 */
const useDockedToolbarPosition = (fullscreen?: boolean): Pick<CSSProperties, 'left' | 'right' | 'bottom' | 'marginBottom'> => {
  const navOpen = useNavOpen();
  const draftContext = useDraftContext();
  const { bannerSettings: { bannerHeightNumber } } = useAuth();

  let left = navOpen ? OPEN_BAR_WIDTH : SMALL_BAR_WIDTH;
  if (fullscreen) left = 0;

  return {
    left,
    right: 'var(--chatbot-sidebar-width, 0px)',
    bottom: draftContext ? DRAFT_TOOLBAR_HEIGHT : 0,
    marginBottom: bannerHeightNumber,
  };
};

export default useDockedToolbarPosition;
