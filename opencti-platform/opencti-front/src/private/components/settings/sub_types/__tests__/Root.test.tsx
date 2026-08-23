import React from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Outlet, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import RootSubType from '../Root';

vi.mock('@components/common/entreprise_edition/EEGuard', () => ({
  default: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

vi.mock('../../../../../components/ErrorNotFound', () => ({
  default: () => <div>not-found</div>,
}));

vi.mock('../../../../../components/Loader', () => ({
  default: () => <div>loader</div>,
}));

vi.mock('../fintel_templates/FintelTemplate', () => ({
  default: () => <div>fintel-template</div>,
}));

vi.mock('../entity_setting/EntitySettingAttributesCard', () => ({
  default: () => <div>entity-setting-attributes</div>,
}));

vi.mock('../entity_setting/EntitySettingCustomFields', () => ({
  default: () => <div>entity-setting-custom-fields</div>,
}));

vi.mock('../entity_setting/EntitySettingCustomOverview', () => ({
  default: () => <div>entity-setting-custom-overview</div>,
}));

vi.mock('../fintel_templates/FintelTemplatesManager', () => ({
  default: () => <div>fintel-templates-manager</div>,
}));

vi.mock('../custom_views/CustomViewEdition', () => ({
  default: () => <div>custom-view-edition</div>,
}));

vi.mock('../custom_views/CustomViewsSettings', () => ({
  default: () => <div>custom-views-settings</div>,
}));

vi.mock('../SubTypeOutletContext', () => ({
  SUBTYPE_TAB_ATTRIBUTES: 'attributes',
  SUBTYPE_TAB_CUSTOM_VIEWS: 'custom-views',
  SUBTYPE_TAB_OVERVIEW_LAYOUT: 'overview-layout',
  SUBTYPE_TAB_TEMPLATES: 'templates',
  SUBTYPE_TAB_WORKFLOW: 'workflow',
  SUBTYPE_TABS: ['workflow', 'attributes', 'templates', 'overview-layout', 'custom-views'],
  useSubTypeOutletContext: () => ({
    tabs: {
      workflow: true,
      attributes: true,
      templates: true,
      'overview-layout': true,
      'custom-views': true,
    },
  }),
}));

vi.mock('../../../../../utils/hooks/useHelper', () => ({
  default: () => ({
    isFeatureEnable: (flag: string) => flag === 'ENTITIES_WORKFLOW',
  }),
}));

vi.mock('../SubType', () => ({
  default: () => <Outlet />,
}));

vi.mock('../SubTypeWorkflow', () => ({
  default: () => <div>graph-editor</div>,
}));

vi.mock('../global_workflow_request_access/GlobalWorkflowSettingsCard', () => ({
  default: () => <div>legacy-card</div>,
}));

describe('RootSubType', () => {
  it('renders the graph editor for a non-DraftWorkspace type when ENTITIES_WORKFLOW is enabled', () => {
    render(
      <MemoryRouter initialEntries={['/dashboard/settings/customization/entity_types/Incident/workflow']}>
        <Routes>
          <Route path="/dashboard/settings/customization/entity_types/:subTypeId/*" element={<RootSubType />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByText('graph-editor')).toBeInTheDocument();
  });
});
