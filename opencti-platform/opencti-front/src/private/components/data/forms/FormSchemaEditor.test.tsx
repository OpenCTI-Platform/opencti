import { screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import FormSchemaEditor from './FormSchemaEditor';

vi.mock('../../common/form/CreatedByField', () => ({ default: () => null }));
vi.mock('../../common/form/ObjectAssigneeField', () => ({ default: () => null }));
vi.mock('../../common/form/ObjectParticipantField', () => ({ default: () => null }));
vi.mock('../../common/form/AuthorizedMembersField', () => ({ default: () => null }));

const entitySettings = {
  edges: [{
    node: {
      target_type: 'Report',
      attributesDefinitions: [{
        name: 'name',
        label: 'Name',
        type: 'string',
        mandatory: true,
      }],
    },
  }],
};

describe('FormSchemaEditor field mapping', () => {
  it.each([
    ['Created By', 'createdBy'],
    ['Marking Definitions', 'objectMarking'],
  ])('preserves the automatic field type when mapping to %s inside a form', async (label, type) => {
    const onChange = vi.fn();
    const { user } = testRender(
      <form>
        <FormSchemaEditor entitySettings={entitySettings} onChange={onChange} />
      </form>,
      { userContext: createMockUserContext({ schema: { sdos: [{ id: 'Report' }] } }) },
    );

    await user.click(screen.getByRole('button', { name: 'Add field' }));
    await user.click(screen.getAllByRole('combobox', { name: 'Map to attribute' })[1]);
    await user.click(await screen.findByRole('option', { name: label }));

    await waitFor(() => {
      expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({
        fields: expect.arrayContaining([
          expect.objectContaining({
            type,
            attributeMapping: expect.objectContaining({ attributeName: type }),
          }),
        ]),
      }));
    });
  });
});
