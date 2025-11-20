import { fieldSpacingContainerStyle } from '../../../../../../utils/field';
import ObjectOrganizationField from '../../../../common/form/ObjectOrganizationField';

const PlaybookFlowFieldOrganizations = () => {
  return (
    <ObjectOrganizationField
      multiple
      alert={false}
      name="organizations"
      label="Target organizations"
      style={fieldSpacingContainerStyle}
    />
  );
};

export default PlaybookFlowFieldOrganizations;
