import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

// Every field of a playbook step form that the component schema lists as required must show the
// required mark ("*" and aria-required). The form builds one element per schema property; this
// guard reads that builder and the dedicated field components so a new branch cannot drop the mark.

const DIR = 'src/private/components/data/playbooks/playbookFlow';
const read = (relative: string) => readFileSync(path.resolve(relative), 'utf8')
  .replace(/\/\*[\s\S]*?\*\//g, ' ')
  .replace(/(^|[^:])\/\/.*$/gm, '$1');

// Components rendered by the builder that take no required mark, and why.
const EXEMPT: Record<string, string> = {
  PlaybookFlowFieldAccessRestrictions: 'an access table with its own add-member form, it renders no field label',
  PlaybookFlowFieldInPirFilters: 'a PIR filter editor, never in a required list',
  PlaybookFlowFieldFilters: 'a filter editor; a missing filter is an empty filter group, not an empty field',
  PlaybookFlowFieldActions: 'a list of action rows, each row validates its own fields',
  PlaybookFlowFieldBoolean: 'a switch always holds a value',
  PlaybookFlowFieldRunAs: 'never in a required list',
};

const builder = () => {
  const source = read(`${DIR}/PlaybookFlowForm.tsx`);
  const start = source.indexOf('([propName, property]) => {');
  const end = source.indexOf('<FormButtonContainer>');
  expect(start).toBeGreaterThan(-1);
  expect(end).toBeGreaterThan(start);
  return source.slice(start, end);
};

describe('playbook step form: required marks', () => {
  it('passes required from the schema to every field element the builder renders', () => {
    const elements = [...builder().matchAll(/<([A-Z]\w*)\b[\s\S]*?\/?>/g)]
      .filter(([, tag]) => tag !== 'SelectItem');
    expect(elements.length).toBeGreaterThan(10);
    const unmarked = elements
      .filter(([, tag]) => !(tag in EXEMPT))
      .filter(([element]) => !element.includes('required={requiredProperties.includes(propName)}'))
      .map(([, tag]) => tag);
    expect(unmarked).toEqual([]);
  });

  it.each([
    'PlaybookFlowFieldAuthorizedMembers',
    'PlaybookFlowFieldTargets',
    'PlaybookFlowFieldOrganizations',
    'PlaybookFlowFieldCaseTemplates',
    'PlaybookFlowFieldPeriod',
    'PlaybookFlowFieldString',
    'PlaybookFlowFieldNumber',
    'PlaybookFlowFieldArray',
  ])('%s forwards required to the field it renders', (name) => {
    const source = read(`${DIR}/playbookFlowFields/${name}.tsx`);
    expect(source).toMatch(/required\??:\s*boolean/);
    expect(source).toMatch(/\srequired=\{required\}/);
  });

  it('PlaybookFlowFieldTriggerTime marks the day selects and the time picker', () => {
    const source = read(`${DIR}/playbookFlowFields/PlaybookFlowFieldTriggerTime.tsx`);
    expect(source.match(/\srequired=\{required\}/g)?.length).toBe(2);
    expect(source).toMatch(/label: t_i18n\('Time'\),\s*required,/);
  });

  it('the shared fields behind them render the mark', () => {
    expect(read('src/private/components/common/form/ObjectMembersField.tsx')).toMatch(/\srequired=\{required\}/);
    expect(read('src/private/components/common/form/CaseTemplateField.tsx')).toMatch(/\srequired=\{required\}/);
    expect(read('src/components/fields/PeriodicityField.tsx')).toMatch(/<InputLabel[^>]*required=\{required\}/);
  });
});
