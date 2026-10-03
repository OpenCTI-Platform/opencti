import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import { applyIndent, HuntCodeEditor } from './HuntCodeEditor';

describe('HuntCodeEditor', () => {
  it('shows the placeholder while the value is empty', () => {
    testRender(<HuntCodeEditor value="" onChange={() => {}} label="Sigma rule" language="sigma" placeholder="title: Example" testId="editor" />);
    expect(screen.getByTestId('editor-placeholder')).toHaveTextContent('title: Example');
  });

  it('highlights the value instead of the placeholder once it is not empty', () => {
    testRender(<HuntCodeEditor value="title: Typed" onChange={() => {}} label="Sigma rule" language="sigma" placeholder="title: Example" testId="editor" />);
    expect(screen.queryByTestId('editor-placeholder')).toBeNull();
    expect(screen.getByTestId('editor')).toHaveTextContent('title: Typed');
  });
});

describe('applyIndent', () => {
  it('inserts an indentation at the caret', () => {
    const result = applyIndent('detection:', 10, 10, false);
    expect(result).toEqual({ value: 'detection:  ', selectionStart: 12, selectionEnd: 12 });
  });

  it('indents every line of a selection', () => {
    const value = 'a: 1\nb: 2\nc: 3';
    const result = applyIndent(value, 0, 9, false);
    expect(result.value).toEqual('  a: 1\n  b: 2\nc: 3');
    expect(result.selectionStart).toEqual(2);
    expect(result.selectionEnd).toEqual(13);
  });

  it('outdents every line of a selection', () => {
    const value = '  a: 1\n  b: 2';
    const result = applyIndent(value, 2, 13, true);
    expect(result.value).toEqual('a: 1\nb: 2');
    expect(result.selectionStart).toEqual(0);
    expect(result.selectionEnd).toEqual(9);
  });

  it('does not outdent past the start of a line', () => {
    const result = applyIndent(' a: 1', 1, 1, true);
    expect(result.value).toEqual('a: 1');
    expect(result.selectionStart).toEqual(0);
  });
});
