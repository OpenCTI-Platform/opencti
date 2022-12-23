import { expect, test } from 'vitest';
import renderer from 'react-test-renderer';
import React from 'react';
import ReportCreation from '../private/components/analysis/reports/ReportCreation';

function toJson(component: renderer.ReactTestRenderer) {
  const result = component.toJSON();
  expect(result).toBeDefined();
  expect(result).not.toBeInstanceOf(Array);
  return result as renderer.ReactTestRendererJSON;
}

test('Data Source component', () => {
  const component = renderer.create(
    <ReportCreation />,
  );
  let tree = toJson(component);
  expect(tree).toMatchSnapshot();

  // // manually trigger the callback
  // tree.props.onMouseEnter();

  // re-rendering
  tree = toJson(component);
  expect(tree).toMatchSnapshot();
});
