/* eslint-disable func-names */
/* eslint-disable no-useless-catch */
import { accountAxios, organizationAxios } from '../utils/axios';
import { toastAxiosError } from '../utils/bakedToast';

export const getAccount = async () => {
  try {
    const response = accountAxios.get('cyio/account', {
      headers: {
        Accept: 'application/vnd.dl.cyio.account+json;version=1',
        'content-type': 'application/vnd.dl.cyio.account+json;version=1',
      },
    });
    return await response;
  } catch (error) {
    toastAxiosError('Account Fetch Error');
    throw error;
  }
};

export const isAuthClient = async () => {
  if (localStorage.getItem('client_id')) {
    return getAccount().then(() => true);
  }
  return false;
};

export const getOrganizationSettings = async (clientId) => {
  try {
    const response = organizationAxios.get('/cyio/organization/settings', {
      headers: {
        Accept: 'application/vnd.dl.cyio.organization.settings+json;version=1',
        'content-type':
          'application/vnd.dl.cyio.organization.settings+json;version=1',
        'X-Cyio-Client': clientId,
      },
    });
    return await response;
  } catch (error) {
    toastAxiosError('Fetch Organization Error');
    throw error;
  }
};

export const updateOrganizationSettings = async (
  clientId,
  params,
) => {
  try {
    const response = organizationAxios.patch(
      '/cyio/organization/settings',
      params,
      {
        headers: {
          Accept:
            'application/vnd.dl.cyio.organization.settings.fragment+json;version=1',
          'content-type':
            'application/vnd.dl.cyio.organization.settings.fragment+json;version=1',
          'X-Cyio-Client': clientId,
        },
      },
    );
    return await response;
  } catch (error) {
    toastAxiosError('Update Organization Error');
    throw error;
  }
};
