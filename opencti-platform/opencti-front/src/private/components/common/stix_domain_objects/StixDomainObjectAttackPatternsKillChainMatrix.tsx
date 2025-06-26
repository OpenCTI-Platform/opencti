import React, { FunctionComponent } from 'react';
import { TargetEntity } from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import {
  StixDomainObjectAttackPatternsKillChainContainer_data$data,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainContainer_data.graphql';
import AttackPatternsMatrix from '../../techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrix';

interface StixDomainObjectAttackPatternsKillChainMatrixProps {
  searchTerm: string;
  data: StixDomainObjectAttackPatternsKillChainContainer_data$data;
  handleAdd: (entity: TargetEntity) => void;
  selectedKillChain: string;
  entityType: string;
  attackPatternIdsToOverlap?: string[];
  isModeOnlyActive: boolean;
}
const StixDomainObjectAttackPatternsKillChainMatrix: FunctionComponent<StixDomainObjectAttackPatternsKillChainMatrixProps> = (
  {
    searchTerm,
    data,
    handleAdd,
    selectedKillChain,
    entityType,
    attackPatternIdsToOverlap,
    isModeOnlyActive,
  },
) => {
  const attackPatterns = (data.attackPatterns?.edges ?? []).map((n) => n.node);
  return (
    <AttackPatternsMatrix
      attackPatterns={attackPatterns}
      searchTerm={searchTerm}
      entityType={entityType}
      handleAdd={handleAdd}
      selectedKillChain={selectedKillChain}
      attackPatternIdsToOverlap={attackPatternIdsToOverlap}
      isModeOnlyActive={isModeOnlyActive}
    />
  );
};

export default StixDomainObjectAttackPatternsKillChainMatrix;
