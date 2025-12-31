import Button from '@common/button/Button';
import React, { FunctionComponent, useContext, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import {
  StixCoreRelationshipCreationFromEntityHeader_stixCoreObject$key,
} from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipCreationFromEntityHeader_stixCoreObject.graphql';
import { useFormatter } from '../../../../components/i18n';
import Drawer from '../drawer/Drawer';
import { TargetEntity } from './StixCoreRelationshipCreationFromEntity';
import StixCoreRelationshipCreationHeaderButtons from './StixCoreRelationshipCreationHeaderButtons';
import StixCoreRelationshipCreationSelectEntityStage from './StixCoreRelationshipCreationSelectEntityStage';
import StixCoreRelationshipCreationFormStage from './StixCoreRelationshipCreationFormStage';
import { CreateRelationshipContext } from './CreateRelationshipContextProvider';
import { computeTargetStixCyberObservableTypes, computeTargetStixDomainObjectTypes } from '../../../../utils/stixTypeUtils';
import { PaginationOptions } from '../../../../components/list_lines';

/**
 * This file contains the code for the "Create Relationship" button in the top
 * right of entity pages and the associated drawer that opens.
 * This workflow is based off the StixCoreRelationshipCreationFromEntity.tsx
 * file, but attempting to move away from the floating action button and grant
 * the user more flexibility in where they can create relationships from.
 */

const relationshipCreationFromEntityFragment = graphql`
  fragment StixCoreRelationshipCreationFromEntityHeader_stixCoreObject on StixCoreObject {
    id
    ...StixCoreRelationshipCreationSelectEntityStage_stixCoreObject
    ...StixCoreRelationshipCreationFormStage_stixCoreObject
  }
`;

interface StixCoreRelationshipCreationFromEntityHeaderProps {
  data: StixCoreRelationshipCreationFromEntityHeader_stixCoreObject$key;
}

const StixCoreRelationshipCreationFromEntityHeader: FunctionComponent<
  StixCoreRelationshipCreationFromEntityHeaderProps
> = ({ data }) => {
  const { t_i18n } = useFormatter();
  const stixCoreObject = useFragment(relationshipCreationFromEntityFragment, data);

  // Fetch from context
  const { state: {
    stixCoreObjectTypes = [],
  } } = useContext(CreateRelationshipContext);

  // Compute SDOs and SCOs
  const targetStixDomainObjectTypes = computeTargetStixDomainObjectTypes(stixCoreObjectTypes);
  const targetStixCyberObservableTypes = computeTargetStixCyberObservableTypes(stixCoreObjectTypes);

  const [targetEntities, setTargetEntities] = useState<TargetEntity[]>([]);

  // Drawer and form control
  const [open, setOpen] = useState<boolean>(false);
  const [step, setStep] = useState<number>(0);
  const [searchPaginationOptions, setSearchPaginationOptions] = useState<PaginationOptions>({});
  const handleOpen = () => setOpen(true);
  const handleClose = () => {
    setOpen(false);
    setStep(0);
    setTargetEntities([]);
  };
  const handleResetSelection = () => {
    setStep(0);
    setTargetEntities([]);
  };

  const storageKey = `stixCoreRelationshipCreationFromEntity-${stixCoreObject.id}-${targetStixDomainObjectTypes.join('-')}-${targetStixCyberObservableTypes.join('-')}`;

  return (
    <>
      {/* The controlled dial to open the drawer */}
      <Button
        onClick={handleOpen}
        variant="secondary"
        style={{ marginLeft: '6px' }}
      >
        {t_i18n('Create Relationship')}
      </Button>

      <Drawer
        title={t_i18n('Create a relationship')}
        open={open}
        onClose={handleClose}
        header={(
          // Create entity and/or observable buttons; only appear in first step
          <StixCoreRelationshipCreationHeaderButtons
            show={step < 1}
            showSDOs={targetStixDomainObjectTypes.length > 0}
            showSCOs={targetStixCyberObservableTypes.length > 0}
            actualTypeFilterValues={[
              ...targetStixDomainObjectTypes,
              ...targetStixCyberObservableTypes,
            ]}
            searchPaginationOptions={searchPaginationOptions}
          />
        )}
      >
        {step === 0
          ? (
              <StixCoreRelationshipCreationSelectEntityStage
                handleNextStep={() => setStep(1)}
                storageKey={storageKey}
                data={stixCoreObject}
                targetEntities={targetEntities}
                setTargetEntities={setTargetEntities}
                virtualEntityTypes={stixCoreObjectTypes}
                handleClose={handleClose}
                setSearchPaginationOptions={setSearchPaginationOptions}
              />
            ) : (
              <StixCoreRelationshipCreationFormStage
                targetEntities={targetEntities}
                handleResetSelection={handleResetSelection}
                handleClose={handleClose}
                data={stixCoreObject}
              />
            )
        }
      </Drawer>
    </>
  );
};

export default StixCoreRelationshipCreationFromEntityHeader;
