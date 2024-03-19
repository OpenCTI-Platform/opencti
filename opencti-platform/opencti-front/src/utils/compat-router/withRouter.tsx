import React from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';

/** @deprecated Use `React Router hooks` instead */
export interface WithRouterProps {
  location: ReturnType<typeof useLocation>;
  params: Record<string, string>;
  navigate: ReturnType<typeof useNavigate>;
}

/** @deprecated Use `React Router hooks` instead */
const withRouter = <Props extends WithRouterProps>(
  Component: React.ComponentType<Props>,
) => {
  // eslint-disable-next-line react/display-name
  return (props: Omit<Props, keyof WithRouterProps>) => {
    const location = useLocation();
    const params = useParams();
    const navigate = useNavigate();

    return <Component {...(props as Props)}
      location={location}
      params={params}
      navigate={navigate}
           />;
  };
};

export default withRouter;
