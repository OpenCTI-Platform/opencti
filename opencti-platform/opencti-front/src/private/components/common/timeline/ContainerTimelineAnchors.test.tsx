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
