import { describe, expect, it } from "vitest";
import { completeDirectoryQuery, directChildPaths, directoryQueryFor } from "./options";

describe("completeDirectoryQuery", () => {
  const found = [
    "/home/user/workspace/paseo/packages/app/src/background-work",
    "/home/user/workspace",
    "/home/user/workspace/couvre-feu",
    "/home/user/workspace/netlens-android",
    "/home/user/workspace/netlens-ios",
    "/home/user/notes",
  ];

  it("completes a lone prefix match with a separator, ignoring fuzzy hits elsewhere", () => {
    expect(completeDirectoryQuery("/home/user/work", found)).toBe("/home/user/workspace/");
  });

  it("completes to the shared start when several folders match", () => {
    expect(completeDirectoryQuery("/home/user/workspace/net", found)).toBe(
      "/home/user/workspace/netlens-",
    );
  });

  it("takes the first match once the shared start is already typed", () => {
    expect(completeDirectoryQuery("/home/user/workspace/netlens-", found)).toBe(
      "/home/user/workspace/netlens-android/",
    );
  });

  it("lists the first child after a trailing separator but never the folder itself", () => {
    expect(completeDirectoryQuery("/home/user/workspace/", found)).toBe(
      "/home/user/workspace/couvre-feu/",
    );
    expect(completeDirectoryQuery("/home/user/workspace/couvre-feu/", found)).toBeNull();
  });

  it("matches case-insensitively and keeps the typed parent as typed", () => {
    expect(completeDirectoryQuery("/home/user/WORK", found)).toBe("/home/user/workspace/");
  });

  it("completes under ~ without knowing the home folder, from the shallowest hits", () => {
    expect(completeDirectoryQuery("~/work", found)).toBe("~/workspace/");
  });

  it("never offers the typed path itself as its own completion", () => {
    const withTyped = ["/home/user/live", ...found, "/home/user/livetest-projects"];
    expect(completeDirectoryQuery("/home/user/live", withTyped)).toBe(
      "/home/user/livetest-projects/",
    );
    expect(completeDirectoryQuery("~/live", ["~/live", "/home/user/livetest-projects"])).toBe(
      "~/livetest-projects/",
    );
  });

  it("completes from the root and needs a path to work from", () => {
    expect(completeDirectoryQuery("/us", ["/usr", "/home/usr"])).toBe("/usr/");
    expect(completeDirectoryQuery("work", found)).toBeNull();
    expect(completeDirectoryQuery("  ", found)).toBeNull();
  });

  it("uses a backslash for a Windows path", () => {
    expect(completeDirectoryQuery("C:\\Users\\jo", ["C:/Users/joe"])).toBe("C:\\Users\\joe\\");
  });
});

describe("directChildPaths", () => {
  it("keeps only the folders inside the folder a trailing separator names", () => {
    const found = [
      "/home/user/workspace",
      "/home/user/workspace/paseo/packages/app",
      "/home/user/workspace/couvre-feu",
      "/home/user/workspace/etat-major",
    ];
    expect(directChildPaths("/home/user/workspace/", found)).toEqual([
      "/home/user/workspace/couvre-feu",
      "/home/user/workspace/etat-major",
    ]);
  });

  it("leaves a query without a trailing separator alone", () => {
    expect(directChildPaths("/home/user/work", ["/a/b"])).toEqual(["/a/b"]);
  });
});

describe("directoryQueryFor", () => {
  it("adds one separator in the style of the path", () => {
    expect(directoryQueryFor("/home/user")).toBe("/home/user/");
    expect(directoryQueryFor("/home/user/")).toBe("/home/user/");
    expect(directoryQueryFor("C:\\Users")).toBe("C:\\Users\\");
  });
});
