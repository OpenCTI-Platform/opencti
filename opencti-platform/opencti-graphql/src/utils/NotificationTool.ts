import { marked } from 'marked';

export default class NotificationTool {
  markdownToHtml(markdownText?: string): string | undefined {
    if (!markdownText) return undefined;
    return marked(markdownText) as string;
  }
}
