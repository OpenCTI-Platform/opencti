import React, { Suspense } from 'react';
import { act, fireEvent, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { useFragment, useLazyLoadQuery } from 'react-relay';
import { MockPayloadGenerator } from 'relay-test-utils';
import taskQuery from './__generated__/RootTaskQuery.graphql';
import taskFragment from './__generated__/Tasks_tasks.graphql';
import type { RootTaskQuery } from './__generated__/RootTaskQuery.graphql';
import type { Tasks_tasks$key } from './__generated__/Tasks_tasks.graphql';
import TaskDetails from './TaskDetails';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';

const Harness = () => {
  const query = useLazyLoadQuery<RootTaskQuery>(taskQuery, { id: 'task-1' });
  const task = useFragment<Tasks_tasks$key>(taskFragment, query.task);
  return task && <TaskDetails tasksData={task} />;
};

const setup = async (task: { workflow_completed: boolean; completes_containment: boolean }, capability = 'KNOWLEDGE_KNUPDATE') => {
  const rendered = testRender(<Suspense><Harness /></Suspense>, {
    userContext: createMockUserContext({ me: { capabilities: [{ name: capability }], capabilitiesInDraft: [] } }),
  });
  await act(async () => rendered.relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
    Task: () => ({ id: 'task-1', entity_type: 'Task', description: 'Isolate the mail server', customFieldValues: [], ...task }),
  })));
  return rendered;
};

describe('TaskDetails containment', () => {
  it('offers the containment switch once the task is in the last status of its workflow, and saves it', async () => {
    const { relayEnv } = await setup({ workflow_completed: true, completes_containment: false });
    const toggle = screen.getByRole('switch');
    expect(toggle).toHaveAttribute('aria-checked', 'false');
    expect(screen.getByTestId('task-containment')).toHaveTextContent('This task completes the containment');
    fireEvent.click(toggle);
    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.node.params.name).toBe('TasksEditionOverviewFieldPatchMutation');
    expect(operation.request.variables.input).toEqual([{ key: 'completes_containment', value: [true] }]);
  });

  it('never offers it on a task that is not completed', async () => {
    await setup({ workflow_completed: false, completes_containment: false });
    expect(screen.queryByTestId('task-containment')).toBeNull();
  });

  it('keeps showing it while it is set, read-only for users who cannot edit the task', async () => {
    await setup({ workflow_completed: false, completes_containment: true }, 'KNOWLEDGE');
    expect(screen.queryByRole('switch')).toBeNull();
    expect(screen.getByTestId('task-containment')).toHaveTextContent('This task completes the containment');
  });
});
