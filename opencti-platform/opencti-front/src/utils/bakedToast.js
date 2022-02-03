import { toast } from 'react-toastify';

const baseCloseTime = 4000;

export const toastGenericError = () => {
  toast.error(
    'An error has occurred',
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
