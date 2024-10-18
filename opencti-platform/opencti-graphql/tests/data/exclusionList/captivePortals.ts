import { exclusionListEntityType, type ExclusionListProperties } from '../../../src/utils/exclusionListTypes';

const list = [
  'android.clients.google.com',
  'apple.com',
  'captive.apple.com',
  'clients3.google.com',
  'clients4.google.com',
  'connectivitycheck.android.com',
  'connectivitycheck.gstatic.com',
  'd2uzsrnmmf6tds.cloudfront.net',
  'detectportal.firefox.com',
  'msftncsi.com',
  'spectrum.s3.amazonaws.com',
  'www.airport.us',
  'www.androidbak.net',
  'www.apple.com',
  'www.appleiphonecell.com',
  'www.google.com',
  'www.gstatic.com',
  'www.ibook.info',
  'www.itools.info',
  'www.msftconnecttest.com',
  'www.thinkdifferent.us'
];

export const captivePortalsList: ExclusionListProperties = {
  name: 'captivePortalsList',
  type: [exclusionListEntityType.DOMAIN_NAME, exclusionListEntityType.URL],
  list,
  actions: null,
};
