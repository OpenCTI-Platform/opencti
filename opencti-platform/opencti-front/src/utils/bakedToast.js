import { toast } from 'react-toastify';

const baseCloseTime = 4000;

export const toastGenericError = (message) => {
  toast.error(
    message || 'An error has occurred',
    {
      theme: 'dark',
      autoClose: baseCloseTime,
    },
  );
};

export const toastAxiosError = (message) => {
  toast.error(
    message || 'Data Fetch Error',
    {
      theme: 'dark',
      autoClose: baseCloseTime,
    },
  );
};
