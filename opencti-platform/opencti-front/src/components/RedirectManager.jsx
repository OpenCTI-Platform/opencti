import React from 'react';
import { useNavigate } from 'react-router-dom';
import { MESSAGING$ } from '../relay/environment';

export const RedirectManager = (props) => {
  const navigate = useNavigate();
  MESSAGING$.redirect.subscribe({
    next: (url) => navigate(url),
  });

  return <>{props.children}</>;
};

export default RedirectManager;
