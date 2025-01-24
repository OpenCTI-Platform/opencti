import { describe, expect, it } from 'vitest';
import { checkFintelTemplateWidgetsValidity } from '../../../src/modules/fintelTemplate/fintelTemplate-domain';
import { type FintelTemplateWidget, WidgetPerspective } from '../../../src/generated/graphql';

describe('fintel template domain utils', () => {
  it('should check fintel template widgets variable names validity', async () => {
    // -- list widgets --
    // no error
    let fintelTemplateWidgets: FintelTemplateWidget[] = [{
      variable_name: 'List1',
      widget: {
        id: 'widget1',
        dataSelection: [],
        type: 'list',
        perspective: WidgetPerspective.Entities,
      },
    }];
    checkFintelTemplateWidgetsValidity(fintelTemplateWidgets); // no expect, it should work
    // should have a variable_name with no space
    fintelTemplateWidgets = [{
      variable_name: 'My list',
      widget: {
        id: 'widget1',
        dataSelection: [],
        type: 'list',
        perspective: WidgetPerspective.Entities,
      },
    }];
    expect(() => checkFintelTemplateWidgetsValidity(fintelTemplateWidgets)).toThrowError('Variable names should not contain spaces or special chars (except - and _)');

    // should have a variable_name with no special character
    fintelTemplateWidgets = [{
      variable_name: '$list',
      widget: {
        id: 'widget1',
        dataSelection: [],
        type: 'list',
        perspective: WidgetPerspective.Entities,
      },
    }];
    expect(() => checkFintelTemplateWidgetsValidity(fintelTemplateWidgets)).toThrowError('Variable names should not contain spaces or special chars (except - and _)');
    // -- attribute widgets --
    // should have a variable_name with no special character
    fintelTemplateWidgets = [{
      variable_name: 'attribute_widget',
      widget: {
        id: 'widget1',
        dataSelection: [{
          instance_id: 'SELF_ID',
          columns: [
            { attribute: 'representative.main', label: 'Representative', variableName: 'representative' },
          ],
        }],
        type: 'attribute',
      },
    }];
    checkFintelTemplateWidgetsValidity(fintelTemplateWidgets); // no expect, it should work
    // should have a variable_name with no special character
    fintelTemplateWidgets = [{
      variable_name: 'attribute&Widget',
      widget: {
        id: 'widget1',
        dataSelection: [{
          instance_id: 'SELF_ID',
          columns: [
            { attribute: 'representative.main', label: 'Representative', variableName: 'representative' },
          ],
        }],
        type: 'attribute',
      },
    }];
    expect(() => checkFintelTemplateWidgetsValidity(fintelTemplateWidgets)).toThrowError('Variable names should not contain spaces or special chars (except - and _)');
    // all the columns should have a variable name
    fintelTemplateWidgets = [{
      variable_name: 'attribute_widget',
      widget: {
        id: 'widget1',
        dataSelection: [{
          instance_id: 'SELF_ID',
          columns: [
            { attribute: 'representative.main', label: 'Representative', variableName: 'representative' },
            { attribute: 'published', label: 'Publication date' },
          ],
        }],
        type: 'attribute',
      },
    }];
    expect(() => checkFintelTemplateWidgetsValidity(fintelTemplateWidgets)).toThrowError('Attributes should all have a variable name');
    // the columns should have a variable name with no space
    fintelTemplateWidgets = [{
      variable_name: 'attribute_widget',
      widget: {
        id: 'widget1',
        dataSelection: [{
          instance_id: 'SELF_ID',
          columns: [
            { attribute: 'representative.main', label: 'Representative', variableName: 'representative' },
            { attribute: 'published', label: 'Publication date', variableName: 'Publication date' },
          ],
        }],
        type: 'attribute',
      },
    }];
    expect(() => checkFintelTemplateWidgetsValidity(fintelTemplateWidgets)).toThrowError('Variable names should not contain spaces or special chars (except - and _)');
    // the columns should have a variable name with no special character
    fintelTemplateWidgets = [{
      variable_name: 'attribute_widget',
      widget: {
        id: 'widget1',
        dataSelection: [{
          instance_id: 'SELF_ID',
          columns: [
            { attribute: 'representative.main', label: 'Representative', variableName: 'representative' },
            { attribute: 'published', label: 'Publication date', variableName: 'Publication/date' },
          ],
        }],
        type: 'attribute',
      },
    }];
    expect(() => checkFintelTemplateWidgetsValidity(fintelTemplateWidgets)).toThrowError('Variable names should not contain spaces or special chars (except - and _)');
  });
});
