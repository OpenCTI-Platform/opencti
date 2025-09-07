import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { isNotEmptyField } from '../utils';

export const useBaseHrefAbsolute = () => {
  const location = useLocation();
  useEffect(() => {
    const fullUrl = window.location.href;
    const baseUrl = fullUrl.endsWith('/') ? fullUrl : `${fullUrl}/`;
    let baseTag = document.querySelector('base');
    const isNewTag = !baseTag;
    if (!baseTag) {
      baseTag = document.createElement('base');
    }
    const previousHref = baseTag.getAttribute('href');
    baseTag.setAttribute('href', baseUrl);
    if (isNewTag) {
      document.head.insertBefore(baseTag, document.head.firstChild);
    }
    return () => {
      if (baseTag) {
        if (isNewTag) {
          baseTag.remove();
        } else if (previousHref) {
          baseTag.setAttribute('href', previousHref);
        } else {
          baseTag.removeAttribute('href');
        }
      }
    };
  }, [location.pathname, location.search, location.hash]);
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
