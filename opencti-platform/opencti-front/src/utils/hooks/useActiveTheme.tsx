import { useLazyLoadQuery, graphql } from 'react-relay';
import type { useActiveThemeQuery } from './__generated__/useActiveThemeQuery.graphql';

const userThemeQuery = graphql`
  query useActiveThemeQuery($themeId: ID!) {
    theme(id: $themeId) {
      id
      name
      theme_background
      theme_paper
      theme_nav
      theme_primary
      theme_secondary
      theme_accent
      theme_text_color
      theme_logo
      theme_logo_collapsed
      theme_logo_login
    }
  }
`;

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
}

const useActiveTheme = ({ userThemeId, platformTheme }: UseActiveThemeParams) => {
  const themeIdToFetch = (userThemeId && userThemeId !== 'default')
    ? userThemeId
    : platformTheme?.id;

  const themeData = themeIdToFetch
    ? useLazyLoadQuery<useActiveThemeQuery>(
      userThemeQuery,
      { themeId: themeIdToFetch },
      { fetchPolicy: 'store-or-network' },
    )
    : null;

  const fetchedTheme = themeData?.theme;
  const activeTheme = themeData?.theme || platformTheme || null;

  const userThemeWasDeleted = !!(themeIdToFetch && !fetchedTheme);

  return {
    activeTheme,
    userThemeWasDeleted,
  };
};

export default useActiveTheme;
