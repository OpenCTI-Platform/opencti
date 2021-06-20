const id = 'rule_confidence';
const name = 'Confidence manager';
const description =
  'This rule will compute the confidence level of any entity or relation. ' +
  'It will translate the reliability of the creator to a confidence ';
const scopeFields = [`confidence`];
const scopeFilters = { types: ['Stix-Domain-Object', 'stix-core-relationship'] };

const definition = { id, name, description, scopeFields, scopeFilters };
export default definition;
