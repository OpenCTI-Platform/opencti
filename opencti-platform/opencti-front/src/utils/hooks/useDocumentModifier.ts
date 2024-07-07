import { useEffect } from 'react';
import { isNotEmptyField } from '../utils';

export const useDocumentTitleModifier = (title: string) => {
  useEffect(() => {
    const prevTitle = document.title;
    if (prevTitle !== title) {
      document.title = title;
    }
    return () => {
      document.title = prevTitle;
    };
  });
};

export const useDocumentLangModifier = (lang: string) => {
  useEffect(() => {
    const prevLang = document.documentElement.lang;
    if (prevLang !== lang) {
      document.documentElement.lang = lang;
    }
    return () => {
      document.documentElement.lang = prevLang;
    };
  });
};

export const useDocumentFaviconModifier = (href?: string | null) => {
  useEffect(() => {
    const element = document.getElementById('favicon');
    const favicon = element as HTMLLinkElement;
    const prevIcon = favicon.href;
    if (isNotEmptyField(href) && prevIcon !== href) {
      favicon.href = href;
    }
    return () => {
      favicon.href = prevIcon;
    };
  });
};

export const useDocumentThemeModifier = (theme: string) => {
  useEffect(() => {
    document.body.setAttribute('data-theme', theme);
  }, []);
};
