import React, { FunctionComponent, useState } from 'react';
import StixCoreRelationshipCreationFromEntity, { TargetEntity } from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';

interface AddVulnerabilitiesProps {
  securityCoverage: {
    id: string;
  };
  _securityCoverageVulnerabilities?: ReadonlyArray<{
    readonly node: {
      readonly id: string;
    };
  }> | Array<{
    node: {
      id: string;
    };
  }>;
}

const AddVulnerabilities: FunctionComponent<AddVulnerabilitiesProps> = ({
  securityCoverage,
  _securityCoverageVulnerabilities,
}) => {
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
