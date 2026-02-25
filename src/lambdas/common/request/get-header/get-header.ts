export const getHeader = (
  headers: Record<string, string | undefined>,
  header: string,
): string | undefined => {
  const [, headerValue] =
    Object.entries(headers)
      .reverse()
      .find(([key]) => key.toLowerCase() === header.toLowerCase()) ?? [];
  return headerValue;
};
