import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { addStixCyberObservable, stixCyberObservableDelete } from '../../src/domain/stixCyberObservable';
import { promoteObservableToIndicator as promoteObservableToIndicator_deprecated } from '../../src/modules/stixCyberObservable/deprecated/stixCyberObservable-domain';
import { ADMIN_USER, testContext } from '../utils/testQuery';
import { stixDomainObjectDelete } from '../../src/domain/stixDomainObject';
import { queryAsAdminWithSuccess } from '../utils/testQueryHelper';

const LIST_QUERY = gql`
  query indicators(
    $filters: FilterGroup
  ) {
    indicators(
      filters: $filters
    ) {
      edges {
        node {
          id
        }
      }
    }
  }
`;

describe('stixCyberObservable deprecated API [>=6.2 & <6.8]', () => {
  it('Promote observable to indicator shall return the observable', async () => {
    const observable = await addStixCyberObservable(testContext, ADMIN_USER, {
      type: 'Domain-Name',
      DomainName: {
        value: 'Test.Promote.Domain'
      },
    });
    expect(observable).not.toBeUndefined();

    const result = await promoteObservableToIndicator_deprecated(testContext, ADMIN_USER, observable.id);
    expect(result).not.toBeUndefined();
    expect(result.id).toEqual(observable.id);

    // we need to find the indicator created to be able to delete it in afterAll
    const queryResult = await queryAsAdminWithSuccess({
      query: LIST_QUERY,
      variables: {
        filters: {
          mode: 'or',
          filters: [{ key: 'name', operator: 'eq', mode: 'and', values: ['Test.Promote.Domain'] }],
          filterGroups: [],
        }
      }
    });
    const createdIndicatorId = queryResult.data?.indicators.edges?.[0].node?.id;
    expect(createdIndicatorId).not.toBeUndefined();

    // cleanup
    await stixCyberObservableDelete(testContext, ADMIN_USER, observable.id);
    await stixDomainObjectDelete(testContext, ADMIN_USER, createdIndicatorId);
  });
});
