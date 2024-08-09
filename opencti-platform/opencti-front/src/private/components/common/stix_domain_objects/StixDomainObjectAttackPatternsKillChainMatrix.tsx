import React, { FunctionComponent } from 'react';
import { TargetEntity } from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import {
  StixDomainObjectAttackPatternsKillChainContainer_data$data,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainContainer_data.graphql';
import AttackPatternsMatrix from '../../techniques/attack_patterns/AttackPatternsMatrix';

interface StixDomainObjectAttackPatternsKillChainMatrixProps {
  searchTerm: string;
  data: StixDomainObjectAttackPatternsKillChainContainer_data$data;
  handleToggleColorsReversed: () => void;
  currentColorsReversed: boolean;
  handleAdd: (entity: TargetEntity) => void;
}
const StixDomainObjectAttackPatternsKillChainMatrix: FunctionComponent<StixDomainObjectAttackPatternsKillChainMatrixProps> = (
  {
    searchTerm,
    data,
    handleToggleColorsReversed,
    currentColorsReversed,
    handleAdd,
  },
) => {
  const attackPatterns = (data.attackPatterns?.edges ?? []).map((n) => n.node);
  return (
    <AttackPatternsMatrix
      attackPatterns={attackPatterns}
      searchTerm={searchTerm}
      marginRight={true}
      handleToggleColorsReversed={handleToggleColorsReversed}
      currentColorsReversed={currentColorsReversed}
      hideBar={true}
      handleAdd={handleAdd}
    />
  );
};

export default StixDomainObjectAttackPatternsKillChainMatrix;
