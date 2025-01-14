import { useContext } from 'react';
import { UserContext } from '../hooks/useAuth';
import locale from '../BrowserLanguage';
import { aiLanguage } from '../../components/AppIntlProvider';

export const aiName = 'XTM AI';

export const aiUrl = 'https://filigran.io';

export const aiRotatingTexts = [
  'Gathering data',
  'Computing trends and statistics',
  'Inferring facts',
  `Cooking with ${aiName}`,
  'Preparing results',
  'Aligning planets',
];

export const getDefaultAiLanguage = () => {
  // get default language (in English, not in Iso-code) for Ai generation by priority : 1. user language, 2. platform language, 3. browser language
  const { me, settings } = useContext(UserContext);
  const userLanguage = me?.language && me.language !== 'auto' ? me.language : null;
  const platformLanguage = settings?.platform_language && settings.platform_language !== 'auto' ? settings.platform_language : null;
  const defaultLanguageValue = userLanguage || platformLanguage || locale;
  const defaultLanguage = aiLanguage.find((lang) => lang.value === defaultLanguageValue);
  return defaultLanguage ? defaultLanguage.name : 'English';
};
