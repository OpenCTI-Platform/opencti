import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ContainerTimelineEventForm from './ContainerTimelineEventForm';

vi.mock('../form/ObjectMarkingField', () => ({ default: () => null }));
vi.mock('../../../../components/fields/markdownField/MarkdownField', () => ({ default: () => null }));
vi.mock('../../../../components/DateTimePickerField', () => ({ default: () => null }));

const renderForm = () => testRender(
  <ContainerTimelineEventForm containerId="case-1" open={true} event={null} onClose={vi.fn()} onSaved={vi.fn()} />,
);

const pick = async (user: ReturnType<typeof renderForm>['user'], field: string, option: string) => {
  await user.click(screen.getByRole('combobox', { name: field }));
  await user.click(screen.getByRole('option', { name: option }));
};

describe('ContainerTimelineEventForm lane of the event', () => {
  it('starts a new event as a milestone of the response lane', async () => {
    renderForm();
    await screen.findByTestId('timeline-event-form');
    expect(screen.getByRole('combobox', { name: 'Lane' })).toHaveTextContent('Response');
    expect(screen.getByRole('combobox', { name: 'Event' })).toHaveTextContent('Milestone');
  });

  it('moves a response milestone to the response lane, and lets the analyst change the lane again', async () => {
    const { user, relayEnv } = renderForm();
    await screen.findByTestId('timeline-event-form');
    await pick(user, 'Lane', 'Adversary');
    await pick(user, 'Event', 'Containment');
    expect(screen.getByRole('combobox', { name: 'Lane' })).toHaveTextContent('Response');
    await pick(user, 'Lane', 'Detection');
    expect(screen.getByRole('combobox', { name: 'Lane' })).toHaveTextContent('Detection');
    expect(screen.getByRole('combobox', { name: 'Event' })).toHaveTextContent('Containment');
    await user.type(screen.getByRole('textbox', { name: /Title/ }), 'Hosts isolated by the SOC');
    await user.click(screen.getByTestId('timeline-event-form-submit'));
    await vi.waitFor(() => expect(relayEnv.mock.getAllOperations()).toHaveLength(1));
    expect(relayEnv.mock.getMostRecentOperation().request.variables.input).toMatchObject({ lane: 'detection', kind: 'containment' });
  });

  it('keeps the lane picked for an event that has no lane of its own', async () => {
    const { user } = renderForm();
    await screen.findByTestId('timeline-event-form');
    await pick(user, 'Lane', 'Evidence');
    await pick(user, 'Event', 'Sighting');
    expect(screen.getByRole('combobox', { name: 'Lane' })).toHaveTextContent('Evidence');
    await pick(user, 'Event', 'Notification');
    expect(screen.getByRole('combobox', { name: 'Lane' })).toHaveTextContent('Response');
  });
});
