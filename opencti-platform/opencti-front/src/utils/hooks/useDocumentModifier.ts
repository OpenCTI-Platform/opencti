import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { isNotEmptyField } from '../utils';

export const useBaseHrefAbsolute = () => {
  const { origin } = window.location;
  const { pathname } = useLocation();

  useEffect(() => {
    const fullUrl = `${origin}${pathname}`;
    const baseUrl = fullUrl.endsWith('/') ? fullUrl : `${fullUrl}/`;
    document.querySelector('base')?.setAttribute('href', baseUrl);
  }, [pathname]);
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
