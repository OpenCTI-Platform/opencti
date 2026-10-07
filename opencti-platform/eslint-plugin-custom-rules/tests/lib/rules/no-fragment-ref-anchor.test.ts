import { RuleTester } from 'eslint';
import parser from '@typescript-eslint/parser';
import rule from '../../../lib/rules/no-fragment-ref-anchor.ts';

const ruleTester = new RuleTester({
  languageOptions: {
    parser,
    ecmaVersion: 2020,
    sourceType: 'module',
    parserOptions: {
      ecmaFeatures: { jsx: true },
    },
  },
});

ruleTester.run('no-fragment-ref-anchor', rule, {
  valid: [
    { code: '<Tooltip title="t"><span>v</span></Tooltip>;' },
    { code: '<Tooltip title="t"><Stack>{v}</Stack></Tooltip>;' },
    { code: '<div><>{v}</></div>;' },
    { code: '<><Tooltip title="t"><span>v</span></Tooltip></>;' },
    { code: '<Drawer><>{v}</></Drawer>;' },
    { code: '<Dialog><>{v}</></Dialog>;' },
    { code: '<Collapse in><>{v}</></Collapse>;' },
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
    {
      code: '<Tooltip title="t">\n  <>{v}</>\n</Tooltip>;',
      errors: [{ messageId: 'fragmentAnchor' }],
    },
    {
      code: '<Tooltip title="t">{/* why */}<>{v}</></Tooltip>;',
      errors: [{ messageId: 'fragmentAnchor' }],
    },
    {
      code: '<Fade in><>{v}</></Fade>;',
      errors: [{ messageId: 'fragmentAnchor', data: { component: 'Fade' } }],
    },
    {
      code: '<Grow in><>{v}</></Grow>;',
      errors: [{ messageId: 'fragmentAnchor', data: { component: 'Grow' } }],
    },
    {
      code: '<Slide in><>{v}</></Slide>;',
      errors: [{ messageId: 'fragmentAnchor', data: { component: 'Slide' } }],
    },
    {
      code: '<Zoom in><>{v}</></Zoom>;',
      errors: [{ messageId: 'fragmentAnchor', data: { component: 'Zoom' } }],
    },
    {
      code: '<ClickAwayListener onClickAway={f}><>{v}</></ClickAwayListener>;',
      errors: [{ messageId: 'fragmentAnchor', data: { component: 'ClickAwayListener' } }],
    },
  ],
});
