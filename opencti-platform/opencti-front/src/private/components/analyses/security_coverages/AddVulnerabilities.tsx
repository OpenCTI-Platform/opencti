import React, { FunctionComponent, useState } from 'react';
import {
  SecurityCoverageVulnerabilities_securityCoverage$data,
} from '@components/analyses/security_coverages/__generated__/SecurityCoverageVulnerabilities_securityCoverage.graphql';
import StixCoreRelationshipCreationFromEntity, { TargetEntity } from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';

interface AddVulnerabilitiesProps {
  securityCoverage: SecurityCoverageVulnerabilities_securityCoverage$data;
  paginationOptions: Record<string, unknown>;
}

const AddVulnerabilities: FunctionComponent<AddVulnerabilitiesProps> = ({ securityCoverage, paginationOptions }) => {
  const [targetEntities, setTargetEntities] = useState<TargetEntity[]>([]);
  const handleOnCreate = () => {
    setTargetEntities([]);
  };
  return (
    <StixCoreRelationshipCreationFromEntity
      entityId={securityCoverage.id}
      objectId={securityCoverage.id}
      connectionKey={'Pagination_vulnerabilities'}
      targetEntities={targetEntities}
      currentView={'relationships'}
      allowedRelationshipTypes={['has-covered']}
      targetStixDomainObjectTypes={['Vulnerability']}
      paginationOptions={paginationOptions}
      paddingRight={220}
      onCreate={handleOnCreate}
      isCoverage={true}
      variant="inLine"
    />
  );
};

export default AddVulnerabilities;
