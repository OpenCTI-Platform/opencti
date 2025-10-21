import React, { FunctionComponent, useState } from 'react';
import {
  SecurityCoverageSecurityPlatforms_securityCoverage$data,
} from '@components/analyses/security_coverages/__generated__/SecurityCoverageSecurityPlatforms_securityCoverage.graphql';
import StixCoreRelationshipCreationFromEntity, { TargetEntity } from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';

interface AddSecurityPlatformsProps {
  securityCoverage: SecurityCoverageSecurityPlatforms_securityCoverage$data;
}

const AddSecurityPlatforms: FunctionComponent<AddSecurityPlatformsProps> = ({ securityCoverage }) => {
  const [targetEntities, setTargetEntities] = useState<TargetEntity[]>([]);
  const handleOnCreate = () => {
    setTargetEntities([]);
  };
  const paginationOptions = {
    count: 25,
    orderBy: 'created_at',
    orderMode: 'asc',
    filters: {
      mode: 'and',
      filters: [],
      filterGroups: [],
    },
  };
  return (
    <StixCoreRelationshipCreationFromEntity
      entityId={securityCoverage.id}
      targetEntities={targetEntities}
      allowedRelationshipTypes={['has-covered']}
      targetStixDomainObjectTypes={['Security-Platform']}
      paginationOptions={paginationOptions}
      paddingRight={220}
      onCreate={handleOnCreate}
      isCoverage={true}
      variant="inLine"
    />
  );
};

export default AddSecurityPlatforms;
