import { Route, Routes } from 'react-router-dom';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';

const DataComponentKnowledge = () => {
  return (
    <>
      <Routes>
        <Route
          path="/relations/:relationId"
          element={
            <StixCoreRelationship />
          }
        />
      </Routes>
    </>
  );
};

export default DataComponentKnowledge;
