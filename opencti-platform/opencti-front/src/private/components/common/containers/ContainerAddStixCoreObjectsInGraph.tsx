import React from 'react';
import useHelper from '../../../../utils/hooks/useHelper';
import ContainerAddStixCoreObjects from './ContainerAddStixCoreObjects';
import ContainerAddStixCoreObjectsInLine from './ContainerAddStixCoreObjectsInLine';

/**
 * Returns either a normal ContainerAddStixCoreObjects component or, if the
 * FAB_REPLACEMENT feature flag is enabled, returns a ContainerAddStixCoreObjectsInLine
 * component with a blue plus controlled dial.
 *
 * Since many of the components that call ContainerAddStixCoreObjects are
 * class components, we cannot use the useHelper hook. So, I've abstracted the
 * switching logic into this function component until the FABs have been
 * removed from the system entirely and the FAB_REPLACEMENT feature flag is
 * redundant.
 */
const ContainerAddStixCoreObjectsInGraph = (
  props: React.ComponentProps<typeof ContainerAddStixCoreObjects>,
) => {
  const { isFeatureEnable } = useHelper();
  const FABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  return FABReplaced
    ? <ContainerAddStixCoreObjectsInLine
        {...props}
      />
    : <ContainerAddStixCoreObjects
        {...props}
      />;
};

export default ContainerAddStixCoreObjectsInGraph;
