import React, { useState } from 'react';
import StixCoreObjectSimulationResult from './StixCoreObjectSimulationResult';

const StixCoreObjectSimulationResultContainer = ({ id, type, data }) => {
  const [simulationType, setSimulationType] = useState('technical');
  return (
    <>
      <StixCoreObjectSimulationResult
        id={id}
        type={type}
        data={data}
        simulationType={simulationType}
        setSimulationType={setSimulationType}
      />
    </>
  );
};
export default StixCoreObjectSimulationResultContainer;
