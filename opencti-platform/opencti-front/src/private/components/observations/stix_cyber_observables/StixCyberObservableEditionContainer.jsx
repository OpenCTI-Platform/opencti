import DrawerHeader from '@common/drawer/DrawerHeader';
import makeStyles from '@mui/styles/makeStyles';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import StixCyberObservableEditionOverview from './StixCyberObservableEditionOverview';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    padding: '10px 20px 20px 20px',
  },
}));

const StixCyberObservableEditionContainer = (props) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { handleClose, stixCyberObservable } = props;
  const { editContext } = stixCyberObservable;

  return (
    <div>
      <DrawerHeader
        title={t_i18n('Update an observable')}
        onClose={handleClose}
        endContent={<SubscriptionAvatars context={editContext} />}
      />

      <div className={classes.container}>
        <StixCyberObservableEditionOverview
          stixCyberObservable={stixCyberObservable}
          enableReferences={useIsEnforceReference('Stix-Cyber-Observable')}
          context={editContext}
          handleClose={handleClose}
        />
      </div>
    </div>
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
