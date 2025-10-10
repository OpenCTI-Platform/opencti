import { RootPrivateQuery$data } from '../../private/__generated__/RootPrivateQuery.graphql';

interface UseActiveThemeParams {
  userThemeId?: string | null;
  platformTheme?: {
    id: string;
    name: string;
    theme_background: string;
    theme_paper: string;
    theme_nav: string;
    theme_primary: string;
    theme_secondary: string;
    theme_accent: string;
    theme_text_color: string;
    theme_logo?: string | null;
    theme_logo_collapsed?: string | null;
    theme_logo_login?: string | null;
  } | null;
  allThemes: RootPrivateQuery$data['themes']; // Add this
}

export const useActiveTheme = ({
  userThemeId,
  platformTheme,
  allThemes,
}: UseActiveThemeParams) => {
  const themes = allThemes?.edges.map((edge) => edge.node) || [];

  const themeIdToFetch = (userThemeId && userThemeId !== 'default')
    ? userThemeId
    : platformTheme?.id;

  const activeTheme = themeIdToFetch
    ? themes.find((theme) => theme.id === themeIdToFetch) || platformTheme
    : platformTheme;

  const userThemeWasDeleted = !!(userThemeId
    && userThemeId !== 'default'
    && !themes.find((t) => t.id === userThemeId));

  return {
    activeTheme,
    userThemeWasDeleted,
  };
};

export default useActiveTheme;
