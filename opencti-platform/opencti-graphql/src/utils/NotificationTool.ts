import showdown from 'showdown';

export default class NotificationTool {
  public static markdownToHtml(markdownText: string): string {
    const converter = new showdown.Converter();
    return converter.makeHtml(markdownText);
  }

  // eslint-disable-next-line class-methods-use-this
  m2h(markdownText: string) : string {
    const converter = new showdown.Converter();
    return converter.makeHtml(markdownText);
  }
}
