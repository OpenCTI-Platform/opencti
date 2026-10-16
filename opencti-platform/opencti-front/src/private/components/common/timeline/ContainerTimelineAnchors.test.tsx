import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ContainerTimelineAnchors from './ContainerTimelineAnchors';

const anchors = {
  first_adversary_activity: '2026-02-01T09:00:00.000Z',
  first_detection: '2026-02-03T07:30:00.000Z',
  first_response: '2026-02-03T07:30:20.000Z',
  containment: null,
  closure: null,
};

describe('ContainerTimelineAnchors on the overview card', () => {
  it('lists every anchor with its time to the minute', () => {
    testRender(<ContainerTimelineAnchors anchors={anchors} dense={true} />);
    expect(screen.getAllByRole('listitem')).toHaveLength(5);
    const detection = screen.getByTestId('timeline-anchor-first_detection');
    expect(detection).toHaveTextContent('First detection');
    expect(detection).toHaveTextContent('2026');
    expect(detection.textContent).not.toMatch(/:\d\d:\d\d/);
  });

  it('tells the time elapsed since the first adversary activity', () => {
    testRender(<ContainerTimelineAnchors anchors={anchors} dense={true} />);
    expect(screen.getByTestId('timeline-anchor-first_detection-elapsed')).toHaveTextContent(/1d 22h later/);
    expect(screen.getByTestId('timeline-anchor-first_adversary_activity-elapsed')).toBeEmptyDOMElement();
    expect(screen.getByTestId('timeline-anchor-containment-elapsed')).toBeEmptyDOMElement();
  });

  it('says when an anchor is not reached yet', () => {
    testRender(<ContainerTimelineAnchors anchors={anchors} dense={true} />);
    expect(screen.getByTestId('timeline-anchor-containment')).toHaveTextContent('Not reached');
    expect(screen.getByTestId('timeline-anchor-closure')).toHaveTextContent('Not reached');
  });
});

describe('ContainerTimelineAnchors headline dates', () => {
  const customized = { ...anchors, eradication: '2026-02-04T10:00:00.000Z', recovery: null, notification: '2026-02-05T10:00:00.000Z' };

  it('shows the headline dates of the type only, in their order', () => {
    testRender(<ContainerTimelineAnchors anchors={customized} headlineDates={['first_detection', 'eradication', 'notification']} />);
    expect(screen.getAllByRole('listitem').map((item) => item.querySelector('[data-testid]')?.getAttribute('data-testid'))).toEqual([
      'timeline-anchor-first_detection',
      'timeline-anchor-eradication',
      'timeline-anchor-notification',
    ]);
    expect(screen.getByTestId('timeline-anchor-eradication')).toHaveTextContent('Eradication');
    expect(screen.queryByTestId('timeline-anchor-closure')).toBeNull();
  });

  it('puts more than six tiles on two balanced rows', () => {
    const every = ['first_adversary_activity', 'first_detection', 'first_response', 'containment', 'eradication', 'recovery', 'notification', 'closure'] as const;
    testRender(<ContainerTimelineAnchors anchors={customized} headlineDates={every} />);
    expect(screen.getByTestId('timeline-anchors').style.gridTemplateColumns).toEqual('repeat(4, minmax(0, 1fr))');
  });

  it('counts no time elapsed from a first adversary activity the type does not show', () => {
    testRender(<ContainerTimelineAnchors anchors={customized} dense={true} headlineDates={['first_detection', 'eradication']} />);
    expect(screen.getByTestId('timeline-anchor-first_detection-elapsed')).toBeEmptyDOMElement();
    expect(screen.getByTestId('timeline-anchor-eradication-elapsed')).toBeEmptyDOMElement();
  });
});

describe('ContainerTimelineAnchors containment help', () => {
  it('names the tasks on a case, which can record the containment', async () => {
    const { user } = testRender(<ContainerTimelineAnchors anchors={anchors} withTasks={true} />);
    await user.hover(screen.getByTestId('timeline-anchor-containment'));
    const help = await screen.findByRole('tooltip');
    expect(help).toHaveTextContent('First Containment milestone, or first task completed with This task completes the containment switched on');
  });

  it('names the milestone only on an incident, which holds no task', async () => {
    const { user } = testRender(<ContainerTimelineAnchors anchors={anchors} />);
    await user.hover(screen.getByTestId('timeline-anchor-containment'));
    const help = await screen.findByRole('tooltip');
    expect(help).toHaveTextContent('First Containment milestone, added with Add an event');
    expect(help).not.toHaveTextContent(/task/);
  });
});
