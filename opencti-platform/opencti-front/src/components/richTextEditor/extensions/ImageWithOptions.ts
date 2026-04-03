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
        renderHTML: (attrs) => (attrs.alt != null && attrs.alt !== '' ? { alt: String(attrs.alt) } : {}),
      },
      title: {
        default: null,
        renderHTML: (attrs) => (attrs.title != null && attrs.title !== '' ? { title: String(attrs.title) } : {}),
      },
      caption: {
        default: null,
        renderHTML: () => ({}),
      },
      href: {
        default: null,
        renderHTML: () => ({}),
      },
      figureStyle: {
        default: null,
        renderHTML: () => ({}),
      },
      figureClass: {
        default: null,
        renderHTML: () => ({}),
      },
      imgStyle: {
        default: null,
        renderHTML: () => ({}),
      },
    };
  },

  parseHTML() {
    const parseDimension = (styleStr: string | null | undefined, dimension: 'width' | 'height'): number | null => {
      if (!styleStr) return null;
      const regex = new RegExp(`${dimension}\\s*:\\s*([0-9.]+)(px|%)?`, 'i');
      const match = styleStr.match(regex);
      return match && match[1] ? parseInt(match[1], 10) : null;
    };

    const extractDimensions = (figStyle: string | null | undefined, imgStyle: string | null | undefined, attrWidth: number | null, attrHeight: number | null) => {
      const styleWidth = parseDimension(figStyle, 'width') ?? parseDimension(imgStyle, 'width');
      const styleHeight = parseDimension(figStyle, 'height') ?? parseDimension(imgStyle, 'height');

      let finalWidth = styleWidth ?? attrWidth;
      let finalHeight = styleHeight ?? attrHeight;

      // Si le style surcharge la largeur mais pas la hauteur (ou inversement),
      // il faut recalculer l'autre dimension pour respecter le ratio d'origine
      if (styleWidth && !styleHeight && attrWidth && attrHeight) {
        finalHeight = Math.round(styleWidth * (attrHeight / attrWidth));
      } else if (styleHeight && !styleWidth && attrWidth && attrHeight) {
        finalWidth = Math.round(styleHeight * (attrWidth / attrHeight));
      } else if (styleWidth && !styleHeight && !attrHeight) {
        finalHeight = null;
      } else if (styleHeight && !styleWidth && !attrWidth) {
        finalWidth = null;
      }

      return { finalWidth, finalHeight };
    };

    const getFigureAttrs = (node: HTMLElement) => {
      const img = node.querySelector('img');
      if (!img) return false;
      const a = img.closest('a');
      const cap = node.querySelector('figcaption');
      const figStyle = node.getAttribute('style');
      const imgStyle = img.getAttribute('style');

      const attrWidth = img.getAttribute('width') ? parseInt(img.getAttribute('width') ?? '', 10) : null;
      const attrHeight = img.getAttribute('height') ? parseInt(img.getAttribute('height') ?? '', 10) : null;

      const { finalWidth, finalHeight } = extractDimensions(figStyle, imgStyle, attrWidth, attrHeight);

      return {
        src: img.getAttribute('src'),
        alt: img.getAttribute('alt'),
        title: img.getAttribute('title') ?? img.getAttribute('data-title'),
        width: finalWidth,
        height: finalHeight,
        href: a?.getAttribute('href') ?? img.getAttribute('data-href') ?? null,
        caption: cap?.textContent?.trim() ?? img.getAttribute('data-caption') ?? null,
        figureStyle: figStyle ? figStyle.replace(/(width|height)\s*:\s*[^;]+;?/gi, '').trim() : null,
        figureClass: node.getAttribute('class') ?? null,
        imgStyle: imgStyle ? imgStyle.replace(/(width|height)\s*:\s*[^;]+;?/gi, '').trim() : null,
      };
    };
    return [
      { tag: 'figure.image-figure', getAttrs: (node) => (typeof node === 'object' && node instanceof HTMLElement ? getFigureAttrs(node) : false) },
      { tag: 'figure.image', getAttrs: (node) => (typeof node === 'object' && node instanceof HTMLElement ? getFigureAttrs(node) : false) },
      {
        tag: 'img[src]',
        getAttrs: (node) => {
          if (typeof node !== 'object' || !(node instanceof HTMLElement)) return false;
          const fig = node.closest('figure');
          const figStyle = fig?.getAttribute('style');
          const imgStyle = node.getAttribute('style');
          const attrWidth = node.getAttribute('width') ? parseInt(node.getAttribute('width') ?? '', 10) : null;
          const attrHeight = node.getAttribute('height') ? parseInt(node.getAttribute('height') ?? '', 10) : null;

          const { finalWidth, finalHeight } = extractDimensions(figStyle, imgStyle, attrWidth, attrHeight);

          return {
            src: node.getAttribute('src'),
            alt: node.getAttribute('alt'),
            title: node.getAttribute('title') ?? node.getAttribute('data-title'),
            width: finalWidth,
            height: finalHeight,
            href: node.getAttribute('data-href') ?? null,
            caption: node.getAttribute('data-caption') ?? null,
            figureStyle: figStyle ? figStyle.replace(/(width|height)\s*:\s*[^;]+;?/gi, '').trim() : null,
            figureClass: fig?.getAttribute('class') ?? null,
            imgStyle: imgStyle ? imgStyle.replace(/(width|height)\s*:\s*[^;]+;?/gi, '').trim() : null,
          };
        },
      },
    ];
  },

  renderHTML({ node, HTMLAttributes }) {
    const { caption, href, figureStyle, figureClass, imgStyle, ...rest } = node.attrs;
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
    if (imgStyle && String(imgStyle).trim() !== '') {
      imgAttrs['style'] = String(imgStyle).trim();
    }

    // Always wrap in figure.image-figure for CKEditor compatibility (centering, margins)
    const imgTag: [string, Record<string, string>] = ['img', imgAttrs];
    const wrappedImg = hasLink
      ? ['a', { href: String(href).trim(), target: '_blank', rel: 'noopener noreferrer' }, imgTag]
      : imgTag;

    const figAttrs: Record<string, string> = {};
    if (figureClass && String(figureClass).trim() !== '') {
      figAttrs['class'] = `image-figure ${String(figureClass).trim().replace('image-figure', '')}`.replace(/\s+/g, ' ').trim();
    } else {
      figAttrs['class'] = 'image-figure';
    }
    if (figureStyle && String(figureStyle).trim() !== '') {
      figAttrs['style'] = String(figureStyle).trim();
    }

    if (hasCaption) {
      return ['figure', figAttrs, wrappedImg, ['figcaption', {}, captionText]];
    }
    return ['figure', figAttrs, wrappedImg];
  },

  addNodeView() {
    if (typeof document === 'undefined') return null;
    const resizeOpts = this.options.resize;
    const resizeEnabled = resizeOpts?.enabled && resizeOpts?.directions?.length;

    return ({ node, getPos, HTMLAttributes, editor }) => {
      const { caption, href, width, height, figureStyle, figureClass, imgStyle, ...imgRest } = node.attrs as Record<string, unknown>;
      const hasCaption = caption && typeof caption === 'string';
      const hasLink = href && String(href).trim() !== '';

      const img = document.createElement('img');
      img.src = HTMLAttributes.src ?? '';

      if (imgStyle && String(imgStyle).trim() !== '') {
        img.setAttribute('style', String(imgStyle).trim());
      }
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

        let nodeFigureClass = 'image-figure';
        if (figureClass && String(figureClass).trim() !== '') {
          nodeFigureClass = `image-figure ${String(figureClass).trim().replace('image-figure', '')}`.replace(/\s+/g, ' ').trim();
        }
        figure.className = nodeFigureClass;

        if (figureStyle && String(figureStyle).trim() !== '') {
          figure.setAttribute('style', String(figureStyle).trim());
        }

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
      let nodeFigureClass = 'image-figure';
      if (figureClass && String(figureClass).trim() !== '') {
        nodeFigureClass = `image-figure ${String(figureClass).trim().replace('image-figure', '')}`.replace(/\s+/g, ' ').trim();
      }
      figure.className = nodeFigureClass;

      if (figureStyle && String(figureStyle).trim() !== '') {
        figure.setAttribute('style', String(figureStyle).trim());
      }
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
