// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import { makeStyles } from '@mui/styles';
import { graphql, useFragment } from 'react-relay';
import { Route, Switch } from 'react-router-dom';
import { AccountKnowledge_financialAccount$key } from './__generated__/AccountKnowledge_financialAccount.graphql';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import AccountPopover from './AccountPopover';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
}));

const accountKnowledgeFragment = graphql`
  fragment AccountKnowledge_financialAccount on FinancialAccount {
    id
    name: name
  }
`;

const AccountKnowledgeComponent = ({
  accountData,
}: {
  accountData: AccountKnowledge_financialAccount$key;
}) => {
  const classes = useStyles();
  const account = useFragment<AccountKnowledge_financialAccount$key>(
    accountKnowledgeFragment,
    accountData,
  );
  const link = `/dashboard/financial/accounts/${account.id}/knowledge`;
  return (
    <div className={classes.container}>
      <StixDomainObjectHeader
        entityType={'Financial-Account'}
        disableSharing={true}
        stixDomainObject={account}
        PopoverComponent={<AccountPopover id={account.id} />}
      />
      <Switch>
        <Route
          exact
          path="/dashboard/financial/accounts/:accountId/knowledge/overview"
          render={(routeProps) => (
            <StixDomainObjectKnowledge
              stixDomainObjectId={account.id}
              stixDomainObjectType="Financial-Account"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/financial/accounts/:accountId/knowledge/organizations"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={account.id}
              relationshipTypes={['belongs-to', 'owns']}
              stixCoreObjectTypes={['Organization']}
              entityLink={link}
              allDirections={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/financial/accounts/:accountId/knowledge/individuals"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={account.id}
              relationshipTypes={['owns']}
              stixCoreObjectTypes={['Individual']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/financial/accounts/:accountId/knowledge/threat_actors"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={account.id}
              relationshipTypes={['owns']}
              stixCoreObjectTypes={['Threat-Actor']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/financial/accounts/:accountId/knowledge/related"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={account.id}
              relationshipTypes={['related-to']}
              stixCoreObjectTypes={[
                'Threat-Actor',
                'Individual',
                'Organization',
              ]}
              entityLink={link}
              allDirections={true}
              {...routeProps}
            />
          )}
        />
      </Switch>
    </div>
  );
};

export default AccountKnowledgeComponent;
