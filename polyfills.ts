// Polyfills for runtime environments missing recent ECMAScript APIs.

if (typeof String.prototype.replaceAll !== "function") {
  const escapeRegExp = (text: string): string =>
    text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  // eslint-disable-next-line no-extend-native
  String.prototype.replaceAll = function (searchValue, replaceValue) {
    const target = String(this);
    if (searchValue instanceof RegExp) {
      if (!searchValue.global) {
        throw new TypeError("replaceAll requires a global RegExp");
      }
      return target.replace(searchValue, replaceValue as string);
    }
    const pattern = new RegExp(escapeRegExp(String(searchValue)), "g");
    return target.replace(pattern, replaceValue as string);
  };
}
