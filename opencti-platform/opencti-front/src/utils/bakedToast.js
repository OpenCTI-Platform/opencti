/* eslint-disable no-console */
import { toast } from 'react-toastify';

const baseCloseTime = 4000;

export const toastInfo = (message) => {
  if (message === undefined) {
    console.debug('can\'t toast with no message');
    return;
  }
  toast.info(message, {
    autoClose: baseCloseTime,
  });
};

export const toastSuccess = (message) => {
  if (message === undefined) {
    console.debug('can\'t toast with no message');
    return;
  }
  toast.success(message, {
    autoClose: baseCloseTime,
  });
};

export const toastWarn = (message) => {
  if (message === undefined) {
    console.debug('can\'t toast with no message');
    return;
  }
  toast.warn(message, {
    autoClose: baseCloseTime,
  });
};

export const toastGenericError = (message) => {
  toast.error(
    message || 'An error has occurred',
    {
      autoClose: baseCloseTime,
    },
  );
};

export const toastAxiosError = (message) => {
  toast.error(
    message || 'Data Fetch Error',
    {
      autoClose: baseCloseTime,
    },
  );
};
