import { describe, expect, it } from "vitest";

import { safeNext } from "./safe-next";

describe("safeNext", () => {
  it.each([
    ["/findings/0b7c", "/findings/0b7c"],
    ["/findings?status=open#top", "/findings?status=open#top"],
    ["/", "/"],
  ])("keeps the same-origin path %s", (raw, expected) => {
    expect(safeNext(raw)).toBe(expected);
  });

  it.each([
    null,
    undefined,
    "",
    "//evil.example",
    "///evil.example",
    "/\\evil.example",
    "\\\\evil.example",
    "https://evil.example/",
    "javascript:alert(1)",
    "evil.example",
    "%2F%2Fevil.example",
    "/%2F%2Fevil.example",
    "%252F%252Fevil.example",
    "/%5Cevil.example",
    "/%09/evil.example",
    "/ok\n",
    "%E0%A4%A",
    "/.//evil.example",
    "/..//evil.example",
    "/%2e//evil.example",
    "/%2E%2E//evil.example",
    "/findings/../..//evil.example/findings/0b7c",
    "/findings/./x",
    "/findings/%2e%2e/admin",
    `/${"a".repeat(3000)}`,
  ])("rejects %j", (raw) => {
    expect(safeNext(raw)).toBe("/");
  });
});
