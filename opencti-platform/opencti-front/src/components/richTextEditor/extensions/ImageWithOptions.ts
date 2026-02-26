import Image from '@tiptap/extension-image';
import { mergeAttributes, ResizableNodeView } from '@tiptap/core';

export interface ImageWithOptionsOptions {
  inline: boolean;
  allowBase64: boolean;
  resize?: {
    enabled: boolean;
    directions: string[];
    minWidth: number;
    minHeight: number;
    alwaysPreserveAspectRatio: boolean;
  };
  HTMLAttributes: Record<string, unknown>;
}

/**
 * Extends Tiptap Image with: alt, title, caption, and optional link (href).
 * Renders as <figure class="image-figure">(<a href?>)<img>(<figcaption>)</figure>
 * for caption and link support. Resize (poignées) is configured on the base Image.
 */
export const ImageWithOptions = Image.extend<ImageWithOptionsOptions>({
  addAttributes() {
    return {
      ...this.parent?.(),
      alt: {
        default: null,
        parseHTML: (element) => {
          const img = element.tagName === 'IMG' ? element : element.querySelector('img');
          return img?.getAttribute('alt') ?? null;
        },
        renderHTML: (attrs) => (attrs.alt != null && attrs.alt !== '' ? { alt: String(attrs.alt) } : {}),
      },
      title: {
        default: null,
        parseHTML: (element) => {
          const img = element.tagName === 'IMG' ? element : element.querySelector('img');
          return img?.getAttribute('title') ?? null;
        },
        renderHTML: (attrs) => (attrs.title != null && attrs.title !== '' ? { title: String(attrs.title) } : {}),
      },
      caption: {
        default: null,
        parseHTML: (element) => {
          const fig = element.tagName === 'FIGURE' ? element : element.closest('figure');
          const cap = fig?.querySelector('figcaption');
          return cap?.textContent?.trim() ?? null;
        },
        renderHTML: () => ({}),
      },
      href: {
        default: null,
        parseHTML: (element) => {
          const img = element.tagName === 'IMG' ? element : element.querySelector('img');
          const a = img?.closest('a');
          return a?.getAttribute('href') ?? null;
        },
        renderHTML: () => ({}),
      },
    };
  },

  parseHTML() {
    const getFigureAttrs = (node: HTMLElement) => {
      const img = node.querySelector('img');
      if (!img) return false;
      const a = img.closest('a');
      const cap = node.querySelector('figcaption');
      return {
        src: img.getAttribute('src'),
        alt: img.getAttribute('alt'),
        title: img.getAttribute('title') ?? img.getAttribute('data-title'),
        width: img.getAttribute('width') ? parseInt(img.getAttribute('width') ?? '', 10) : null,
        height: img.getAttribute('height') ? parseInt(img.getAttribute('height') ?? '', 10) : null,
        href: a?.getAttribute('href') ?? img.getAttribute('data-href') ?? null,
        caption: cap?.textContent?.trim() ?? img.getAttribute('data-caption') ?? null,
      };
    };
    return [
      { tag: 'figure.image-figure', getAttrs: (node) => (typeof node === 'object' && node instanceof HTMLElement ? getFigureAttrs(node) : false) },
      {
        tag: 'img[src]',
        getAttrs: (node) => {
          if (typeof node !== 'object' || !(node instanceof HTMLElement)) return false;
          return {
            src: node.getAttribute('src'),
            alt: node.getAttribute('alt'),
            title: node.getAttribute('title') ?? node.getAttribute('data-title'),
            width: node.getAttribute('width') ? parseInt(node.getAttribute('width') ?? '', 10) : null,
            height: node.getAttribute('height') ? parseInt(node.getAttribute('height') ?? '', 10) : null,
            href: node.getAttribute('data-href') ?? null,
            caption: node.getAttribute('data-caption') ?? null,
          };
        },
      },
    ];
  },

  renderHTML({ node, HTMLAttributes }) {
    const { caption, href, ...rest } = node.attrs;
    const merged = mergeAttributes(this.options.HTMLAttributes ?? {}, rest, HTMLAttributes);
    // ProseMirror renderSpec requires attribute values to be strings; omit null/undefined
    const imgAttrs: Record<string, string> = {};
    Object.entries(merged).forEach(([key, value]) => {
      if (value != null && value !== '') {
        imgAttrs[key] = String(value);
      }
    });

    const hasCaption = typeof caption === 'string' && caption.trim() !== '';
    const hasLink = href && String(href).trim() !== '';
    const captionText = hasCaption ? String(caption).trim() : '';
    const titleText = typeof node.attrs.title === 'string' && node.attrs.title.trim() !== '' ? node.attrs.title.trim() : '';

    // Redundant data-* attributes for resilience across sanitization pipelines.
    if (captionText) {
      imgAttrs['data-caption'] = captionText;
    }
    if (hasLink) {
      imgAttrs['data-href'] = String(href).trim();
    }
    if (titleText) {
      imgAttrs['data-title'] = titleText;
    }

    // Plain image: return default spec so DOMSerializer/renderSpec get a valid structure
    if (!hasCaption && !hasLink) {
      return ['img', imgAttrs];
    }

    const imgTag: [string, Record<string, string>] = ['img', imgAttrs];
    const wrappedImg = hasLink
      ? ['a', { href: String(href).trim(), target: '_blank', rel: 'noopener noreferrer' }, imgTag]
      : imgTag;
    if (hasCaption) {
      return ['figure', { class: 'image-figure' }, wrappedImg, ['figcaption', {}, captionText]];
    }
    return ['figure', { class: 'image-figure' }, wrappedImg];
  },

  addNodeView() {
    if (typeof document === 'undefined') return null;
    const resizeOpts = this.options.resize;
    const resizeEnabled = resizeOpts?.enabled && resizeOpts?.directions?.length;

    return ({ node, getPos, HTMLAttributes, editor }) => {
      const { caption, href, width, height, ...imgRest } = node.attrs as Record<string, unknown>;
      const hasCaption = caption && typeof caption === 'string';
      const hasLink = href && String(href).trim() !== '';

      const img = document.createElement('img');
      img.src = HTMLAttributes.src ?? '';
      Object.entries(imgRest).forEach(([key, value]) => {
        if (value != null && value !== '') img.setAttribute(key, String(value));
      });
      if (width != null) img.setAttribute('width', String(width));
      if (height != null) img.setAttribute('height', String(height));

      const showWhenLoaded = (dom: HTMLElement) => {
        dom.style.visibility = 'hidden';
        dom.style.pointerEvents = 'none';
        img.onload = () => {
          dom.style.visibility = '';
          dom.style.pointerEvents = '';
        };
      };

      if (resizeEnabled && resizeOpts) {
        const { directions, minWidth, minHeight, alwaysPreserveAspectRatio } = resizeOpts;
        const nodeView = new ResizableNodeView({
          element: img,
          editor,
          node,
          getPos,
          onResize: (w, h) => {
            img.style.width = `${w}px`;
            img.style.height = `${h}px`;
          },
          onCommit: (w, h) => {
            const pos = getPos();
            if (pos === undefined) return;
            editor.chain().setNodeSelection(pos).updateAttributes(this.name, { width: w, height: h }).run();
          },
          onUpdate: (updatedNode: typeof node) => {
            if (updatedNode.type !== node.type) return false;
            return true;
          },
          options: {
            directions: directions as ('top' | 'right' | 'bottom' | 'left' | 'top-right' | 'top-left' | 'bottom-right' | 'bottom-left')[],
            min: { width: minWidth, height: minHeight },
            preserveAspectRatio: alwaysPreserveAspectRatio === true,
          },
        });

        /* Always use figure wrapper when resize is on so we can show/update caption in update() */
        const figure = document.createElement('figure');
        figure.className = 'image-figure';
        if (hasLink) {
          const a = document.createElement('a');
          a.href = String(href).trim();
          a.target = '_blank';
          a.rel = 'noopener noreferrer';
          a.addEventListener('click', (event) => event.preventDefault());
          a.appendChild(nodeView.dom);
          figure.appendChild(a);
        } else {
          figure.appendChild(nodeView.dom);
        }
        if (hasCaption) {
          const figcap = document.createElement('figcaption');
          figcap.textContent = caption;
          figure.appendChild(figcap);
        }

        showWhenLoaded(figure);

        return {
          dom: figure,
          update: (updatedNode: typeof node, decorations: readonly unknown[], innerDecorations: unknown) => {
            if (updatedNode.type !== node.type) return false;
            const ok = nodeView.update(updatedNode, decorations as never, innerDecorations as never);
            if (!ok) return false;
            const cap = updatedNode.attrs.caption;
            const capEl = figure.querySelector('figcaption');
            if (cap != null && typeof cap === 'string' && cap !== '') {
              if (capEl) capEl.textContent = cap;
              else {
                const fc = document.createElement('figcaption');
                fc.textContent = cap;
                figure.appendChild(fc);
              }
            } else if (capEl) capEl.remove();
            const innerImg = figure.querySelector('img');
            if (innerImg) {
              innerImg.src = updatedNode.attrs.src ?? '';
              ['alt', 'title'].forEach((k) => {
                const v = updatedNode.attrs[k];
                if (v != null) innerImg.setAttribute(k, String(v));
                else innerImg.removeAttribute(k);
              });
            }
            return true;
          },
          destroy: () => nodeView.destroy(),
        };
      }

      const figure = document.createElement('figure');
      figure.className = 'image-figure';
      if (hasLink) {
        const a = document.createElement('a');
        a.href = String(href).trim();
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.addEventListener('click', (event) => event.preventDefault());
        a.appendChild(img);
        figure.appendChild(a);
      } else {
        figure.appendChild(img);
      }
      if (hasCaption) {
        const figcap = document.createElement('figcaption');
        figcap.textContent = caption;
        figure.appendChild(figcap);
      }

      return {
        dom: figure,
        update: (updatedNode: typeof node) => {
          if (updatedNode.type !== node.type) return false;
          const cap = updatedNode.attrs.caption;
          const capEl = figure.querySelector('figcaption');
          if (cap && typeof cap === 'string') {
            if (!capEl) {
              const fc = document.createElement('figcaption');
              fc.textContent = cap;
              figure.appendChild(fc);
            } else capEl.textContent = cap;
          } else if (capEl) capEl.remove();
          const innerImg = figure.querySelector('img');
          if (innerImg) {
            innerImg.src = updatedNode.attrs.src ?? '';
            ['alt', 'title'].forEach((k) => {
              const v = updatedNode.attrs[k];
              if (v != null) innerImg.setAttribute(k, String(v));
              else innerImg.removeAttribute(k);
            });
          }
          return true;
        },
        destroy: () => {},
      };
    };
  },
});
