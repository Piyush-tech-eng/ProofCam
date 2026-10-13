import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL(".", import.meta.url));
const mime = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml" };
const server = createServer(async (req, res) => {
  const path = decodeURIComponent(new URL(req.url ?? "/", "http://localhost").pathname);
  const relative = path === "/" ? "index.html" : normalize(path).replace(/^([/\\]|\.\.(?:[/\\]|$))+/, "");
  try {
    const bytes = await readFile(join(root, relative));
    res.writeHead(200, { "content-type": mime[extname(relative)] ?? "application/octet-stream", "cache-control": "no-store" });
    res.end(bytes);
  } catch {
    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    res.end("Not found");
  }
});
const port = Number(process.env.WEB_PORT ?? 5173);
server.listen(port, "0.0.0.0", () => console.log("ProofCam demo: http://localhost:" + port));
