import { describe, it, expect } from 'vitest';
import removeUnnecessaryHtml from './pdfUnnecessarytHtml';

describe('Utils: removeUnnecessaryHtml', () => {
  it('should remove script tags and their content', () => {
    const html = '<div>Content<script>alert("test");</script>More content</div>';
    const result = removeUnnecessaryHtml(html);
    expect(result).not.toContain('<script>');
    expect(result).not.toContain('alert');
    expect(result).toContain('Content');
    expect(result).toContain('More content');
  });

  it('should remove style tags but preserve inline styles', () => {
    const html = '<style>.class { color: red; }</style><p style="color: blue;">Text</p>';
    const result = removeUnnecessaryHtml(html);
    expect(result).not.toContain('<style>');
    expect(result).toContain('style="color: blue;"');
    expect(result).toContain('Text');
  });

  it('should remove iframe tags', () => {
    const html = '<div>Before<iframe src="https://example.com"></iframe>After</div>';
    const result = removeUnnecessaryHtml(html);
    expect(result).not.toContain('<iframe');
    expect(result).toContain('Before');
    expect(result).toContain('After');
  });

  it('should remove noscript tags', () => {
    const html = '<div>Content<noscript>No JS</noscript>More</div>';
    const result = removeUnnecessaryHtml(html);
    expect(result).not.toContain('<noscript>');
    expect(result).not.toContain('No JS');
    expect(result).toContain('Content');
    expect(result).toContain('More');
  });

  it('should remove HTML comments', () => {
    const html = '<div>Text<!-- This is a comment -->More text</div>';
    const result = removeUnnecessaryHtml(html);
    expect(result).not.toContain('<!--');
    expect(result).not.toContain('This is a comment');
    expect(result).toContain('Text');
    expect(result).toContain('More text');
  });

  it('should remove GIF images', () => {
    const html = '<img src="image.gif" /><img src="photo.jpg" />';
    const result = removeUnnecessaryHtml(html);
    expect(result).not.toContain('image.gif');
    expect(result).toContain('photo.jpg');
  });

  it('should remove id="undefined" attributes', () => {
    const html = '<div id="undefined" class="test">Content</div>';
    const result = removeUnnecessaryHtml(html);
    expect(result).not.toContain('id="undefined"');
    expect(result).toContain('class="test"');
    expect(result).toContain('Content');
  });

  it('should remove empty class attributes', () => {
    const html = '<div class="">Content</div>';
    const result = removeUnnecessaryHtml(html);
    expect(result).not.toContain('class=""');
    expect(result).toContain('Content');
  });

  it('should remove empty style attributes', () => {
    const html = '<div style="">Content</div>';
    const result = removeUnnecessaryHtml(html);
    expect(result).not.toContain('style=""');
    expect(result).toContain('Content');
  });

  it('should clean up multiple consecutive spaces', () => {
    const html = '<div>Text    with    spaces</div>';
    const result = removeUnnecessaryHtml(html);
    expect(result).toContain('Text with spaces');
    expect(result).not.toContain('    ');
  });

  it('should preserve article structure and paragraph content', () => {
    const html = `
      <article>
        <h1>Title</h1>
        <script>tracking();</script>
        <p>First paragraph with important content.</p>
        <!-- Comment -->
        <p>Second paragraph.</p>
        <style>.hidden { display: none; }</style>
      </article>
    `;
    const result = removeUnnecessaryHtml(html);
    expect(result).toContain('<article>');
    expect(result).toContain('<h1>Title</h1>');
    expect(result).toContain('First paragraph with important content.');
    expect(result).toContain('Second paragraph.');
    expect(result).not.toContain('<script>');
    expect(result).not.toContain('tracking()');
    expect(result).not.toContain('<!-- Comment -->');
    expect(result).not.toContain('<style>');
  });

  it('should handle complex nested HTML from news articles', () => {
    const html = `
      <div class="article-container">
        <header>
          <h1>Article Title</h1>
          <style>.header { color: blue; }</style>
        </header>
        <div class="article-body">
          <p class="lead">Lead paragraph with critical info.</p>
          <script async src="ads.js"></script>
          <p>Regular paragraph content.</p>
          <!-- Ad placeholder -->
          <iframe src="https://ads.example.com"></iframe>
          <p>More important content that must be preserved.</p>
          <noscript>Please enable JavaScript</noscript>
        </div>
      </div>
    `;
    const result = removeUnnecessaryHtml(html);
    
    // Verify structure is preserved
    expect(result).toContain('article-container');
    expect(result).toContain('Article Title');
    expect(result).toContain('article-body');
    
    // Verify all paragraphs are preserved
    expect(result).toContain('Lead paragraph with critical info.');
    expect(result).toContain('Regular paragraph content.');
    expect(result).toContain('More important content that must be preserved.');
    
    // Verify unwanted elements are removed
    expect(result).not.toContain('<script');
    expect(result).not.toContain('ads.js');
    expect(result).not.toContain('<style>');
    expect(result).not.toContain('<!-- Ad placeholder -->');
    expect(result).not.toContain('<iframe');
    expect(result).not.toContain('<noscript>');
    expect(result).not.toContain('Please enable JavaScript');
  });
});
