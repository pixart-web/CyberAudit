export const isSafeReturnPath = (value: string) => value.startsWith("/") && !value.startsWith("//");
