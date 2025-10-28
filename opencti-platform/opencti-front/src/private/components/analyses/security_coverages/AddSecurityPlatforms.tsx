import React, { FunctionComponent, useState } from 'react';
import {
  SecurityCoverageSecurityPlatforms_securityCoverage$data,
} from '@components/analyses/security_coverages/__generated__/SecurityCoverageSecurityPlatforms_securityCoverage.graphql';
import StixCoreRelationshipCreationFromEntity, { TargetEntity } from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';

interface AddSecurityPlatformsProps {
  securityCoverage: SecurityCoverageSecurityPlatforms_securityCoverage$data;
  paginationOptions: Record<string, unknown>;
}

const AddSecurityPlatforms: FunctionComponent<AddSecurityPlatformsProps> = ({ securityCoverage, paginationOptions }) => {
  const [targetEntities, setTargetEntities] = useState<TargetEntity[]>([]);
  const handleOnCreate = () => {
    setTargetEntities([]);
  };
  return (
    <StixCoreRelationshipCreationFromEntity
      entityId={securityCoverage.id}
      objectId={securityCoverage.id}
      connectionKey={'Pagination_securityPlatforms'}
      targetEntities={targetEntities}
      currentView={'relationships'}
      allowedRelationshipTypes={['has-covered']}
      targetStixDomainObjectTypes={['SecurityPlatform']}
      paginationOptions={paginationOptions}
      paddingRight={220}
      onCreate={handleOnCreate}
      isCoverage={true}
      variant="inLine"
    />
  );
};

export default AddSecurityPlatforms;
