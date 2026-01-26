import { createFragmentContainer, graphql } from 'react-relay';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import StixCyberObservableEditionOverview from './StixCyberObservableEditionOverview';

const StixCyberObservableEditionContainer = (props) => {
  const { handleClose, stixCyberObservable } = props;
  const { editContext } = stixCyberObservable;

  return (
    <StixCyberObservableEditionOverview
      stixCyberObservable={stixCyberObservable}
      enableReferences={useIsEnforceReference('Stix-Cyber-Observable')}
      context={editContext}
      handleClose={handleClose}
    />
  );
};
const StixCyberObservableEditionFragment = createFragmentContainer(
  StixCyberObservableEditionContainer,
  {
    stixCyberObservable: graphql`
      fragment StixCyberObservableEditionContainer_stixCyberObservable on StixCyberObservable {
        id
        ...StixCyberObservableEditionOverview_stixCyberObservable
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);
export default StixCyberObservableEditionFragment;
