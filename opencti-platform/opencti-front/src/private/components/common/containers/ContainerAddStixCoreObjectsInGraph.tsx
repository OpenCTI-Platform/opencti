import React from 'react';
import ContainerAddStixCoreObjects from './ContainerAddStixCoreObjects';
import ContainerAddStixCoreObjectsInLine from './ContainerAddStixCoreObjectsInLine';

const ContainerAddStixCoreObjectsInGraph = (
  props: React.ComponentProps<typeof ContainerAddStixCoreObjects>,
) => {
  return (
    <ContainerAddStixCoreObjectsInLine
      {...props}
    />
  );
};

export default ContainerAddStixCoreObjectsInGraph;
