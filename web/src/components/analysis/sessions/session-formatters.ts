export function humanize(value: string): string {
  return value.replaceAll("_", " ");
}

export function formatEndpoint(ip: string, port: number): string {
  const host = ip.includes(":") ? `[${ip}]` : ip;
  return `${host}:${port}`;
}

export function pluralize(
  count: number,
  singular: string,
  plural = `${singular}s`,
) {
  return `${count.toLocaleString("en")} ${count === 1 ? singular : plural}`;
}
