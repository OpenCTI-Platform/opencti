import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const useNormalizedUriKey = (uriKey: string) => {
  const navigate = useNavigate();
  const normalizedUriKey = uriKey.toLowerCase();

  useEffect(() => {
    if (uriKey !== normalizedUriKey) {
      navigate(`/${normalizedUriKey}`);
    }
  }, [uriKey, normalizedUriKey, navigate]);

  return normalizedUriKey;
};

export default useNormalizedUriKey;
