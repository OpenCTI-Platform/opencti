import { addTheme } from '../modules/theme/theme-domain';
import { executionContext, SYSTEM_USER } from '../utils/access';

export const up = async (next) => {
  const context = executionContext('migration');
  const themes = [
    {
      name: 'dark',
      theme_accent: '#0f1e38',
      theme_background: '#070d19',
      theme_logo: '',
      theme_logo_collapsed: '',
      theme_logo_login: '',
      theme_nav: '#070d19',
      theme_paper: '#09101e',
      theme_primary: '#0fbcff',
      theme_secondary: '#00f1bd',
    },
    {
      name: 'light',
      theme_accent: '#eeeeee',
      theme_background: '#f8f8f8',
      theme_logo: '',
      theme_logo_collapsed: '',
      theme_logo_login: '',
      theme_nav: '#ffffff',
      theme_paper: '#ffffff',
      theme_primary: '#001bda',
      theme_secondary: '#0c7e69',
    }
  ];

  for (let i = 0; i < themes.length; i += 1) {
    const theme = themes[i];
    await addTheme(context, SYSTEM_USER, theme);
  }

  next();
};

export const down = async (next) => {
  next();
};
