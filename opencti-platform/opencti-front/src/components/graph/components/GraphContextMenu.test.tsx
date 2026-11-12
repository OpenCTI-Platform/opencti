import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import GraphContextMenu, { type GraphContextMenuSection, graphContextMenuSections, registeredSelectionMenuActions } from './GraphContextMenu';
import { registerGraphSelectionAction } from '../badges/graphSelectionActionRegistry';
import { graphNode } from '../../../utils/tests/graphTestData';

describe('GraphContextMenu', () => {
  it('lists the actions of each section under its name, says why one cannot run, and runs the chosen one', async () => {
    const hide = vi.fn();
    const onClose = vi.fn();
    const { user } = testRender(
      <GraphContextMenu
        anchor={{ x: 40, y: 60 }}
        label="Graph actions"
        onClose={onClose}
        sections={[
          { key: 'node', label: 'APT-X', actions: [{ id: 'hide', label: 'Hide', icon: <span />, onSelect: hide }] },
          { key: 'graph', label: 'Graph', actions: [{ id: 'clear', label: 'Clear selection', icon: <span />, shortcut: 'Esc', disabledReason: 'Nothing is selected' }] },
          { key: 'empty', label: 'Nothing to offer', actions: [] },
        ]}
      />,
    );
    const menu = await screen.findByRole('menu', { name: 'Graph actions' });
    expect(within(menu).getByText('APT-X')).toBeInTheDocument();
    expect(within(menu).queryByText('Nothing to offer')).toBeNull();
    expect(within(menu).getByRole('menuitem', { name: /Clear selection/ })).toHaveAttribute('aria-disabled', 'true');
    expect(within(menu).getByText('Nothing is selected')).toBeInTheDocument();
    await user.click(within(menu).getByRole('menuitem', { name: /Hide/ }));
    expect(hide).toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
  });

  it('offers a choice as a submenu', async () => {
    testRender(
      <GraphContextMenu
        anchor={{ x: 0, y: 0 }}
        label="Graph actions"
        onClose={vi.fn()}
        sections={[{
          key: 'graph',
          actions: [{ id: 'select-by-type', label: 'Select by entity type', icon: <span />, options: { items: [{ key: 'Malware', label: 'Malware' }], onSelect: vi.fn() } }],
        }]}
      />,
    );
    const menu = await screen.findByRole('menu', { name: 'Graph actions' });
    expect(within(menu).getByRole('menuitem', { name: /Select by entity type/ })).toHaveAttribute('aria-haspopup', 'menu');
  });

  it('puts the focus on the first action that can run when opened from the keyboard', async () => {
    testRender(
      <GraphContextMenu
        anchor={{ x: 0, y: 0 }}
        label="Graph actions"
        onClose={vi.fn()}
        focusFirstItem
        sections={[{
          key: 'graph',
          actions: [
            { id: 'clear', label: 'Clear selection', icon: <span />, disabledReason: 'Nothing is selected' },
            { id: 'invert', label: 'Invert selection', icon: <span />, onSelect: vi.fn() },
          ],
        }]}
      />,
    );
    const menu = await screen.findByRole('menu', { name: 'Graph actions' });
    await waitFor(() => expect(within(menu).getByRole('menuitem', { name: /Invert selection/ })).toHaveFocus());
  });

  it('opens nothing without a place to open or without an action', () => {
    const { unmount } = testRender(
      <GraphContextMenu anchor={null} label="Graph actions" onClose={vi.fn()} sections={[{ key: 'a', actions: [{ id: 'x', label: 'X', icon: <span /> }] }]} />,
    );
    expect(screen.queryByRole('menu')).toBeNull();
    unmount();
    testRender(<GraphContextMenu anchor={{ x: 0, y: 0 }} label="Graph actions" onClose={vi.fn()} sections={[{ key: 'a', actions: [] }]} />);
    expect(screen.queryByRole('menu')).toBeNull();
  });
});

describe('graphContextMenuSections', () => {
  const section = (key: string, label: string, actionLabel: string): GraphContextMenuSection => ({
    key,
    label,
    actions: [{ id: `${key}-action`, label: actionLabel, icon: <span />, onSelect: vi.fn() }],
  });
  const entity = section('node', 'APT-X', 'Hide');
  const relationship = section('link', 'Uses', 'Select this relationship');
  const graph = section('graph', 'Graph', 'Select all nodes');
  const selection = section('selection', 'Selection', 'Invert selection');
  const targets: [string, GraphContextMenuSection | undefined][] = [['an entity', entity], ['a relationship', relationship], ['the empty canvas', undefined]];
  const renderMenu = (sections: GraphContextMenuSection[]) => testRender(
    <GraphContextMenu anchor={{ x: 0, y: 0 }} label="Graph actions" onClose={vi.fn()} sections={sections} />,
  );

  it.each(targets)('offers the selection, and its inversion, on %s while something is selected', async (_, element) => {
    renderMenu(graphContextMenuSections({ element, selection, graph }));
    const menu = await screen.findByRole('menu', { name: 'Graph actions' });
    expect(within(menu).getByText('Selection')).toBeInTheDocument();
    expect(within(menu).getByRole('menuitem', { name: /Invert selection/ })).toBeInTheDocument();
  });

  it.each(targets)('offers no selection, nor its inversion, on %s while nothing is selected', async (_, element) => {
    renderMenu(graphContextMenuSections({ element, graph }));
    const menu = await screen.findByRole('menu', { name: 'Graph actions' });
    expect(within(menu).queryByText('Selection')).toBeNull();
    expect(within(menu).queryByRole('menuitem', { name: /Invert selection/ })).toBeNull();
  });

  it('puts the selection first on an element of a larger selection and on the empty canvas, after the element otherwise', () => {
    const keys = (sections: GraphContextMenuSection[]) => sections.map(({ key }) => key);
    expect(keys(graphContextMenuSections({ element: entity, selection, graph }))).toEqual(['node', 'selection']);
    expect(keys(graphContextMenuSections({ element: entity, elementInSelection: true, selection, graph }))).toEqual(['selection', 'node']);
    expect(keys(graphContextMenuSections({ element: relationship, selection, graph }))).toEqual(['link', 'selection']);
    expect(keys(graphContextMenuSections({ element: relationship, elementInSelection: true, selection, graph }))).toEqual(['selection', 'link']);
    expect(keys(graphContextMenuSections({ selection, graph }))).toEqual(['selection', 'graph']);
    expect(keys(graphContextMenuSections({ element: entity, graph }))).toEqual(['node']);
    expect(keys(graphContextMenuSections({ graph }))).toEqual(['graph']);
  });
});

describe('registeredSelectionMenuActions', () => {
  const malware = graphNode();
  const selection = { nodes: [malware], links: [] };
  const t_i18n = (message: string) => `t:${message}`;

  it('lists the actions registered for the selection on this surface, disabled with their reason or with their choices', async () => {
    const enrich = vi.fn();
    const cleanups = [
      registerGraphSelectionAction({
        id: 'loading',
        icon: () => null,
        label: (t) => t('Loading action'),
        isAvailable: (_, context) => context === 'investigation',
        disabledReason: (_, t) => t('Loading'),
        options: () => ({ items: [{ key: 'never', label: 'Never shown' }], onSelect: vi.fn() }),
      }),
      registerGraphSelectionAction({
        id: 'enrichment',
        icon: () => null,
        label: (t) => t('Enrichment'),
        isAvailable: (_, context) => context === 'investigation',
        options: (s) => ({ items: s.nodes.map((n) => ({ key: n.id, label: n.label })), onSelect: enrich }),
      }),
    ];
    try {
      expect(registeredSelectionMenuActions(selection, 'correlation', t_i18n)).toEqual([]);
      const actions = registeredSelectionMenuActions(selection, 'investigation', t_i18n);
      expect(actions.map((a) => a.id)).toEqual(['registered-enrichment', 'registered-loading']);

      testRender(<GraphContextMenu anchor={{ x: 0, y: 0 }} label="Graph actions" onClose={vi.fn()} sections={[{ key: 'selection', actions }]} />);
      const menu = await screen.findByRole('menu', { name: 'Graph actions' });
      const loading = within(menu).getByRole('menuitem', { name: /t:Loading action/ });
      expect(loading).toHaveAttribute('aria-disabled', 'true');
      expect(loading).not.toHaveAttribute('aria-haspopup');
      expect(within(menu).getByText('t:Loading')).toBeInTheDocument();
      expect(within(menu).getByRole('menuitem', { name: /t:Enrichment/ })).toHaveAttribute('aria-haspopup', 'menu');

      actions[0].options?.onSelect(malware.id);
      expect(enrich).toHaveBeenCalledWith(malware.id);
    } finally {
      cleanups.forEach((cleanup) => cleanup());
    }
  });

  it('runs an action without choices on the selection', () => {
    const hunt = vi.fn();
    const cleanup = registerGraphSelectionAction({ id: 'hunt', icon: () => null, label: () => 'Hunt', isAvailable: () => true, onSelect: hunt });
    try {
      registeredSelectionMenuActions(selection, undefined, t_i18n)[0].onSelect?.();
      expect(hunt).toHaveBeenCalledWith(selection);
    } finally {
      cleanup();
    }
  });
});
