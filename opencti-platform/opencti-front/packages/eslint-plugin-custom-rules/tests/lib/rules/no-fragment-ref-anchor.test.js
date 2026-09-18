import { RuleTester } from 'eslint';
import parser from '@typescript-eslint/parser';
import rule from '../../../lib/rules/no-fragment-ref-anchor';

const ruleTester = new RuleTester({
  parser,
  parserOptions: {
    ecmaVersion: 2020,
    sourceType: 'module',
    ecmaFeatures: { jsx: true },
  },
});

ruleTester.run('no-fragment-ref-anchor', rule, {
  valid: [
    // An element can hold the ref.
    { code: '<Tooltip title="t"><span>v</span></Tooltip>;' },
    { code: '<Tooltip title="t"><Stack>{v}</Stack></Tooltip>;' },
    // A Fragment anywhere else is none of this rule\'s business.
    { code: '<div><>{v}</></div>;' },
    { code: '<><Tooltip title="t"><span>v</span></Tooltip></>;' },
    // Not one of the components that anchor a ref on their child.
    { code: '<Drawer><>{v}</></Drawer>;' },
    { code: '<Dialog><>{v}</></Dialog>;' },
    // Several children is a different mistake, reported by React itself.
    { code: '<Tooltip title="t"><span>a</span><span>b</span></Tooltip>;' },
  ],

  invalid: [
    {
      code: '<Tooltip title="t"><>{v}</></Tooltip>;',
      errors: [{ messageId: 'fragmentAnchor', data: { component: 'Tooltip' } }],
    },
    {
      code: '<Tooltip title="t"><Fragment>{v}</Fragment></Tooltip>;',
      errors: [{ messageId: 'fragmentAnchor' }],
    },
    {
      code: '<Tooltip title="t"><React.Fragment>{v}</React.Fragment></Tooltip>;',
      errors: [{ messageId: 'fragmentAnchor' }],
    },
    // Surrounding whitespace must not hide the Fragment.
    {
      code: '<Tooltip title="t">\n  <>{v}</>\n</Tooltip>;',
      errors: [{ messageId: 'fragmentAnchor' }],
    },
    // The transition components clone their child the same way.
    {
      code: '<Fade in><>{v}</></Fade>;',
      errors: [{ messageId: 'fragmentAnchor', data: { component: 'Fade' } }],
    },
    {
      code: '<ClickAwayListener onClickAway={f}><>{v}</></ClickAwayListener>;',
      errors: [{ messageId: 'fragmentAnchor', data: { component: 'ClickAwayListener' } }],
    },
  ],
});
