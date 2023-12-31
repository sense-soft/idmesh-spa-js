
const dedupe = (arr: string[]) => Array.from(new Set(arr));

export const getUniqueScopes = (...scopes: (string | undefined)[]) => {
  return dedupe(scopes.filter(Boolean).join(' ').trim().split(/\s+/)).join(' ');
};
