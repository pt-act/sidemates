import path from "node:path";
import { existsSync, lstatSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { promises as fsp } from "node:fs";
import type { WorkspaceFile } from "../shared/types.js";

function isWithin(root: string, target: string) {
  const relative = path.relative(root, target);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

function canonicalRoot(root: string) {
  if (!existsSync(root)) return null;
  try { return realpathSync(root); }
  catch { return null; }
}

export function listWorkspaceFiles(root: string, maxDepth = 5): WorkspaceFile[] {
  const resolvedRoot = path.resolve(root), realRoot = canonicalRoot(resolvedRoot);
  if (!realRoot) return [];

  const visit = (current: string, depth: number): WorkspaceFile[] => {
    if (depth > maxDepth) return [];
    let entries;
    try { entries = readdirSync(current, { withFileTypes: true }); }
    catch { return []; }

    return entries.filter((entry) => !entry.name.startsWith(".") && !entry.isSymbolicLink()).flatMap((entry) => {
      const absolute = path.join(current, entry.name);
      try {
        const stat = lstatSync(absolute);
        if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) return [];
        const canonical = realpathSync(absolute);
        if (!isWithin(realRoot, canonical)) return [];
        const item: WorkspaceFile = {
          path: path.relative(resolvedRoot, absolute),
          size: stat.size,
          modifiedAt: stat.mtime.toISOString(),
          kind: stat.isDirectory() ? "directory" : "file",
        };
        return stat.isDirectory() ? [item, ...visit(absolute, depth + 1)] : [item];
      } catch {
        return [];
      }
    });
  };

  return visit(resolvedRoot, 0);
}

/** Runtime configuration the model runtime imports or obeys in its OWN
 * process. A workspace write to any of these is a startup script, not data:
 * `.opencode/tools/*.ts` and `.opencode/plugins/*.js` are imported at startup,
 * `.opencode/opencode.json` wins the config merge, and `.claude/settings*.json`,
 * `CLAUDE.md` and `AGENTS.md` are re-enabled by --setting-sources. Writing them
 * must never be equivalent to a normal file save. */
const RESERVED_RUNTIME_PATHS = [".opencode", ".claude"] as const;
const RESERVED_RUNTIME_FILES = ["opencode.json", "CLAUDE.md", "AGENTS.md", ".mcp.json"] as const;

export function isReservedRuntimePath(relative: string): boolean {
  const normalized = path.normalize(String(relative || "")).replace(/^[/\\]+/, "").split(path.sep).filter(Boolean);
  if (!normalized.length) return false;
  // Windows paths can arrive with either separator.
  const segments = normalized.flatMap((part) => part.split("/")).filter(Boolean);
  if (!segments.length) return false;
  const head = segments[0]!.toLowerCase();
  if ((RESERVED_RUNTIME_PATHS as readonly string[]).includes(head)) return true;
  // Only the root config files are honoured at that level by the runtimes; a
  // nested `notes/CLAUDE.md` is ordinary data and stays writable.
  return segments.length === 1 && (RESERVED_RUNTIME_FILES as readonly string[]).map((name) => name.toLowerCase()).includes(head);
}

export type WorkspaceFileRead =
  | { ok: true; path: string; content: string }
  | { ok: false; reason: "not_found" | "too_large" };

export function readWorkspaceFile(root: string, relativePath: string, maxBytes = 500_000): WorkspaceFileRead {
  const resolvedRoot = path.resolve(root), target = path.resolve(resolvedRoot, relativePath);
  if (!relativePath || relativePath.length > 2_048 || !isWithin(resolvedRoot, target)) return { ok: false, reason: "not_found" };
  const realRoot = canonicalRoot(resolvedRoot);
  if (!realRoot || !existsSync(target)) return { ok: false, reason: "not_found" };

  try {
    const stat = lstatSync(target);
    if (stat.isSymbolicLink() || !stat.isFile() || !isWithin(realRoot, realpathSync(target))) return { ok: false, reason: "not_found" };
    if (stat.size > maxBytes) return { ok: false, reason: "too_large" };
    return { ok: true, path: path.relative(resolvedRoot, target), content: readFileSync(target, "utf8") };
  } catch {
    return { ok: false, reason: "not_found" };
  }
}

/** Canonical, symlink-aware containment for every host-mediated filesystem
 * operation. Rejects absolute paths, `..` traversal, symlinked segments,
 * canonical (realpath) escapes and alias tricks. Returns the resolved
 * absolute target only when it stays inside the teammate workspace root. */
export async function resolveWorkspacePath(
  root: string,
  relative: string,
  opts: { createParents?: boolean; forWrite?: boolean } = {},
): Promise<{ ok: true; absolute: string; relative: string } | { ok: false; reason: string }> {
  const raw = String(relative ?? "");
  if (!raw || raw.length > 2_048 || raw.includes("\u0000")) return { ok: false, reason: "invalid_path" };
  if (opts.forWrite && isReservedRuntimePath(raw)) return { ok: false, reason: "reserved_runtime_path" };
  const normalized = path.normalize(raw);
  if (path.isAbsolute(raw) || normalized === ".." || normalized.startsWith(`..${path.sep}`)) return { ok: false, reason: "outside_workspace" };
  let realRoot: string;
  try { realRoot = await fsp.realpath(root); } catch { return { ok: false, reason: "no_workspace" }; }
  const target = path.resolve(realRoot, normalized);
  if (target !== realRoot && !target.startsWith(`${realRoot}${path.sep}`)) return { ok: false, reason: "outside_workspace" };
  const parts = path.relative(realRoot, target).split(path.sep).filter(Boolean);
  let current = realRoot;
  for (let index = 0; index < parts.length; index += 1) {
    current = path.join(current, parts[index]!);
    const isParentSegment = index < parts.length - 1;
    try {
      if ((await fsp.lstat(current)).isSymbolicLink()) return { ok: false, reason: "symlink_escape" };
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code !== "ENOENT") return { ok: false, reason: "unreadable" };
      if (opts.createParents && isParentSegment) await fsp.mkdir(current, { mode: 0o700 });
    }
  }
  // Final canonical check: an existing target must realpath back inside root.
  try {
    const real = await fsp.realpath(target);
    if (real !== realRoot && !real.startsWith(`${realRoot}${path.sep}`)) return { ok: false, reason: "canonical_escape" };
  } catch { /* target does not exist yet; parent traversal already checked */ }
  return { ok: true, absolute: target, relative: path.relative(realRoot, target) || path.basename(target) };
}

export async function writeWorkspaceFile(root: string, relative: string, content: string): Promise<{ ok: true; path: string; characters: number } | { ok: false; reason: string }> {
  const body = String(content);
  if (body.length > 1_000_000) return { ok: false, reason: "too_large" };
  const resolved = await resolveWorkspacePath(root, relative, { createParents: true, forWrite: true });
  if (!resolved.ok) return resolved;
  await fsp.writeFile(resolved.absolute, body, { encoding: "utf8", mode: 0o600 });
  return { ok: true, path: resolved.relative, characters: body.length };
}

export async function replaceWorkspaceFile(root: string, relative: string, oldText: string, newText: string): Promise<{ ok: true; path: string } | { ok: false; reason: string }> {
  const resolved = await resolveWorkspacePath(root, relative, { forWrite: true });
  if (!resolved.ok) return resolved;
  const content = await fsp.readFile(resolved.absolute, "utf8").catch(() => null);
  if (content === null) return { ok: false, reason: "not_found" };
  const matches = content.split(oldText).length - 1;
  if (matches !== 1) return { ok: false, reason: `expected_one_match_found_${matches}` };
  await fsp.writeFile(resolved.absolute, content.replace(oldText, newText), { encoding: "utf8", mode: 0o600 });
  return { ok: true, path: resolved.relative };
}
