import { beforeEach, describe, expect, it } from 'vitest';
import { isDomNodeKeptAtExport, EXPORT_KEEP_CLASS, EXPORT_REMOVE_CLASS } from './Image';

const createDomNode = (className: string, parentClassName?: string): HTMLElement => {
  const node = document.createElement('div');
  node.className = className;
  if (parentClassName) {
    const parent = document.createElement('div');
    parent.className = parentClassName;
    parent.appendChild(node);
  }
  return node;
};

describe('Image', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  describe('isDomNodeKeptAtExport', () => {
    it('should keep a node with no special class', () => {
      const node = createDomNode('some-class');
      expect(isDomNodeKeptAtExport(node)).toBe(true);
    });

    it('should keep a node with no class at all', () => {
      const node = document.createElement('div');
      expect(isDomNodeKeptAtExport(node)).toBe(true);
    });

    it('should filter out MuiDialog-root', () => {
      const node = createDomNode('MuiDialog-root');
      expect(isDomNodeKeptAtExport(node)).toBe(false);
    });

    it('should filter out MuiDrawer-docked', () => {
      const node = createDomNode('MuiDrawer-docked');
      expect(isDomNodeKeptAtExport(node)).toBe(false);
    });

    it('should filter out MuiIconButton-root', () => {
      const node = createDomNode('MuiIconButton-root');
      expect(isDomNodeKeptAtExport(node)).toBe(false);
    });

    it('should filter out MuiInputBase-root', () => {
      const node = createDomNode('MuiInputBase-root MuiOutlinedInput-root');
      expect(isDomNodeKeptAtExport(node)).toBe(false);
    });

    it('should keep a node with export-keep class', () => {
      const node = createDomNode(`MuiInputBase-root ${EXPORT_KEEP_CLASS}`);
      document.body.appendChild(node);
      expect(isDomNodeKeptAtExport(node)).toBe(true);
    });

    it('should keep a node inside an export-keep ancestor', () => {
      const parent = document.createElement('div');
      parent.className = EXPORT_KEEP_CLASS;
      const node = document.createElement('div');
      node.className = 'MuiInputBase-root';
      parent.appendChild(node);
      document.body.appendChild(parent);
      expect(isDomNodeKeptAtExport(node)).toBe(true);
    });

    it('should filter out a node with export-remove class', () => {
      const node = createDomNode(EXPORT_REMOVE_CLASS);
      document.body.appendChild(node);
      expect(isDomNodeKeptAtExport(node)).toBe(false);
    });

    it('should filter out a node inside an export-remove ancestor', () => {
      const parent = document.createElement('div');
      parent.className = EXPORT_REMOVE_CLASS;
      const node = document.createElement('div');
      node.className = 'some-class';
      parent.appendChild(node);
      document.body.appendChild(parent);
      expect(isDomNodeKeptAtExport(node)).toBe(false);
    });

    it('should filter out an ignored class node not inside export-keep', () => {
      const parent = document.createElement('div');
      parent.className = 'regular-parent';
      const node = document.createElement('div');
      node.className = 'MuiIconButton-root';
      parent.appendChild(node);
      document.body.appendChild(parent);
      expect(isDomNodeKeptAtExport(node)).toBe(false);
    });

    it('should keep a regular node inside a regular parent', () => {
      const parent = document.createElement('div');
      parent.className = 'regular-parent';
      const node = document.createElement('div');
      node.className = 'regular-child';
      parent.appendChild(node);
      document.body.appendChild(parent);
      expect(isDomNodeKeptAtExport(node)).toBe(true);
    });
  });
});
