import React, { FunctionComponent } from 'react';
import purify from 'dompurify';
import parse from 'html-react-parser';
import { truncate } from '../utils/String';
import FieldOrEmpty from './FieldOrEmpty';
import { isEmptyField } from '../utils/utils';
import useHelper from '../utils/hooks/useHelper';

interface HtmlDisplayProps {
  content: string | null;
  limit?: number;
}

const SANITIZE_CONFIG = {
  ADD_ATTR: ['data-type', 'data-checked', 'title', 'class', 'href', 'src', 'alt', 'width', 'height', 'data-caption', 'data-href', 'data-title', 'colspan', 'rowspan', 'style'],
  ADD_TAGS: ['figure', 'figcaption', 'th', 'colgroup', 'col'],
};

const HtmlDisplay: FunctionComponent<HtmlDisplayProps> = ({ content, limit }) => {
  const { isTiptapEditorEnable } = useHelper();
  const tiptapEnabled = isTiptapEditorEnable();

  if (isEmptyField(content)) {
    return (
      <FieldOrEmpty source={content}>{content}</FieldOrEmpty>
    );
  }

  if (!tiptapEnabled) {
    return (
      <div className="ck-content">
        {limit ? parse(purify.sanitize(truncate(content, limit))) : parse(purify.sanitize(content))}
      </div>
    );
  }

  const sanitize = (html: string) => purify.sanitize(html, SANITIZE_CONFIG);
  const normalizeImageMetadata = (html: string) => {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');
    const imgs = Array.from(doc.querySelectorAll('img'));

    imgs.forEach((img) => {
      const dataTitle = img.getAttribute('data-title');
      const dataHref = img.getAttribute('data-href');
      const dataCaption = img.getAttribute('data-caption');

      if (!img.getAttribute('title') && dataTitle) {
        img.setAttribute('title', dataTitle);
      }

      if (dataHref && !img.closest('a')) {
        const a = doc.createElement('a');
        a.setAttribute('href', dataHref);
        a.setAttribute('target', '_blank');
        a.setAttribute('rel', 'noopener noreferrer');
        const parent = img.parentNode;
        if (parent) {
          parent.replaceChild(a, img);
          a.appendChild(img);
        }
      }

      const hasCaption = typeof dataCaption === 'string' && dataCaption.trim() !== '';
      if (hasCaption && !img.closest('figure')) {
        const figure = doc.createElement('figure');
        figure.setAttribute('class', 'image-figure');
        const figcaption = doc.createElement('figcaption');
        figcaption.textContent = dataCaption.trim();

        const maybeAnchor = img.closest('a');
        const mediaNode = maybeAnchor ?? img;
        const parent = mediaNode.parentNode;
        if (parent) {
          parent.replaceChild(figure, mediaNode);
          figure.appendChild(mediaNode);
          figure.appendChild(figcaption);
        }
      }
    });

    const anchors = Array.from(doc.querySelectorAll('a'));
    anchors.forEach((a) => {
      a.setAttribute('target', '_blank');
      a.setAttribute('rel', 'noopener noreferrer');
    });

    return doc.body.innerHTML;
  };

  return (
    <div className="rich-text-content">
      {parse(normalizeImageMetadata(sanitize(limit ? truncate(content, limit) : content)))}
    </div>
  );
};

export default HtmlDisplay;
