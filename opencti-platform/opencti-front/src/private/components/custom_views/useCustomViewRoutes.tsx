import { Route } from 'react-router-dom';
import RootCustomView from './Root';
import { useCustomViews } from './useCustomViews';

interface useCustomViewRoutesProps {
  entityType: string;
}

const useCustomViewRoutes = ({ entityType }: useCustomViewRoutesProps) => {
  const { customViews } = useCustomViews(entityType);
  return customViews.map(({ path, id }) => (
    <Route key={path} path={path} element={<RootCustomView customViewId={id} />} />
  ));
};

export default useCustomViewRoutes;
