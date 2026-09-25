import { describe, expect, it } from 'vitest';
import { parse, print } from 'graphql';
import { pruneResponseConnections } from '../../../src/graphql/chunk-document-prune';

const flat = (query: string) => print(parse(query)).replace(/\s+/g, ' ').trim();
const pruned = (query: string) => print(pruneResponseConnections(parse(query))).replace(/\s+/g, ' ').trim();

describe('chunk executor: response connections pruned from chunk documents', () => {
  it('drops the observables connection pycti selects on indicatorAdd, keeps the scalars', () => {
    const query = `mutation IndicatorAdd($input: IndicatorAddInput!) { indicatorAdd(input: $input) {
      id standard_id entity_type parent_types observables { edges { node { id standard_id entity_type } } } } }`;
    expect(pruned(query)).toBe(flat('mutation IndicatorAdd($input: IndicatorAddInput!) { indicatorAdd(input: $input) { id standard_id entity_type parent_types } }'));
  });

  it('drops the indicators connection pycti selects on stixCyberObservableAdd', () => {
    const query = `mutation StixCyberObservableAdd($type: String!) { stixCyberObservableAdd(type: $type) {
      id standard_id entity_type parent_types indicators { edges { node { id pattern pattern_type } } } } }`;
    expect(pruned(query)).toBe(flat('mutation StixCyberObservableAdd($type: String!) { stixCyberObservableAdd(type: $type) { id standard_id entity_type parent_types } }'));
  });

  it('leaves documents without a connection unchanged, nested edit selections included', () => {
    const create = 'mutation AttackPatternAdd($input: AttackPatternAddInput!) { attackPatternAdd(input: $input) { id standard_id entity_type parent_types } }';
    const edit = 'mutation Edit($id: ID!, $input: [EditInput]!) { stixDomainObjectEdit(id: $id) { fieldPatch(input: $input) { id standard_id } } }';
    expect(pruned(create)).toBe(flat(create));
    expect(pruned(edit)).toBe(flat(edit));
  });
});
