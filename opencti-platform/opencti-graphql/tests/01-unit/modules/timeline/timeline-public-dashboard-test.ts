import { describe, expect, it } from 'vitest';
import { createPublicManifest } from '../../../../src/modules/publicDashboard/publicDashboard-domain';
import { TIMELINE_WIDGET_TYPE } from '../../../../src/modules/timeline/timeline-types';
import { fromB64 } from '../../../../src/utils/base64';

describe('Timeline widget in public dashboards', () => {
  it('should never publish the case a timeline widget is bound to', () => {
    const manifest = {
      widgets: {
        timeline: {
          id: 'timeline',
          type: TIMELINE_WIDGET_TYPE,
          parameters: { title: 'Ransomware case', container_id: 'b4c2f5a8-6f2e-4b7e-9d0a-2f1e3c4d5a6b', timeline_lanes: ['adversary'], timeline_window: '7d' },
          dataSelection: [{ label: 'Timeline', filters: { mode: 'and', filters: [], filterGroups: [] } }],
        },
        text: { id: 'text', type: 'text', parameters: { content: 'Weekly status', container_id: 'kept-for-other-widgets' }, dataSelection: [] },
      },
    };
    const published = fromB64(createPublicManifest(manifest));
    expect(published.widgets.timeline.parameters).toEqual({ title: 'Ransomware case', timeline_lanes: ['adversary'], timeline_window: '7d' });
    expect(published.widgets.timeline.dataSelection).toEqual([{ label: 'Timeline' }]);
    // Only the widget types bound to a case lose the binding
    expect(published.widgets.text.parameters).toEqual({ content: 'Weekly status', container_id: 'kept-for-other-widgets' });
  });
});
