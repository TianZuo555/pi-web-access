// Smoke test for the FireClaw search provider.
// Spins up a mock FireClaw /api/proxy server and exercises searchWithFireclaw.
// Run: npx tsx tests/fireclaw-smoke.ts
import { createServer, type Server } from "node:http";
import { searchWithFireclaw, isFireclawAvailable } from "../fireclaw.ts";
import { search } from "../gemini-search.ts";

let failures = 0;
function assert(cond: boolean, msg: string) {
	if (cond) {
		console.log(`  ✓ ${msg}`);
	} else {
		failures++;
		console.error(`  ✗ ${msg}`);
	}
}

function startMock(handlers: {
	proxy?: (req: any, body: any, res: any) => void;
	health?: (res: any) => void;
}): Promise<Server> {
	return new Promise((resolve) => {
		const server = createServer((req, res) => {
			let chunks: Buffer[] = [];
			req.on("data", (c: Buffer) => chunks.push(c));
			req.on("end", () => {
				const raw = Buffer.concat(chunks).toString("utf8");
				let body: any = null;
				try { body = raw ? JSON.parse(raw) : null; } catch {}
				if (req.url === "/api/health" && handlers.health) return handlers.health(res);
				if (req.url === "/api/proxy" && handlers.proxy) return handlers.proxy(req, body, res);
				res.writeHead(404, { "Content-Type": "application/json" });
				res.end(JSON.stringify({ error: "not found" }));
			});
		});
		server.listen(0, "127.0.0.1", () => resolve(server));
	});
}

function close(server: Server): Promise<void> {
	return new Promise((r) => server.close(() => r()));
}

async function main() {
	// --- Test 1: happy path ---
	{
		console.log("Test 1: happy-path search maps content + extracts source links");
		let receivedAction = "";
		let receivedBody: any = null;
		let receivedAuth = "";
		const server = await startMock({
			proxy: (req, body, res) => {
				receivedAction = String(req.headers["x-fireclaw-action"]);
				receivedAuth = String(req.headers["authorization"] ?? "");
				receivedBody = body;
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(JSON.stringify({
					content: "FireClaw is an open-source security proxy. See [FireClaw](https://github.com/raiph-ai/fireclaw) and [site](https://fireclaw.app).",
					metadata: { severity: "low", trustTier: "neutral", duration: 42, cached: false },
				}));
			},
		});
		const addr = (server.address() as any);
		const base = `http://127.0.0.1:${addr.port}`;
		process.env.FIRECLAW_BASE_URL = base;

		assert(isFireclawAvailable(), "isFireclawAvailable() true when FIRECLAW_BASE_URL set");

		const result = await searchWithFireclaw("what is fireclaw", { numResults: 5 });
		assert(receivedAction === "search", `proxy received X-FireClaw-Action: search (got "${receivedAction}")`);
		assert(receivedAuth === "", "no Authorization header without api key");
		assert(receivedBody?.query === "what is fireclaw", `query forwarded (got ${JSON.stringify(receivedBody?.query)})`);
		assert(receivedBody?.count === 5, `count forwarded (got ${JSON.stringify(receivedBody?.count)})`);
		assert(!!result, "returned a result");
		assert(result?.answer.includes("open-source security proxy"), "answer maps content");
		assert(result?.results.length === 2, `extracted 2 source links (got ${result?.results.length})`);
		assert(result?.results[0].url === "https://github.com/raiph-ai/fireclaw", "first source URL correct");

		await close(server);
	}

	// --- Test 2: api key forwarded as Bearer ---
	{
		console.log("Test 2: FIRECLAW_API_KEY forwarded as Authorization: Bearer");
		let receivedAuth = "";
		const server = await startMock({
			proxy: (req, body, res) => {
				receivedAuth = String(req.headers["authorization"] ?? "");
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(JSON.stringify({ content: "ok [a](https://a.example)" }));
			},
		});
		const base = `http://127.0.0.1:${(server.address() as any).port}`;
		process.env.FIRECLAW_BASE_URL = base;
		process.env.FIRECLAW_API_KEY = "secret-key";
		await searchWithFireclaw("q");
		assert(receivedAuth === "Bearer secret-key", `Authorization header set (got "${receivedAuth}")`);
		delete process.env.FIRECLAW_API_KEY;
		await close(server);
	}

	// --- Test 3: proxy error surfaces ---
	{
		console.log("Test 3: non-ok proxy response throws");
		const server = await startMock({
			proxy: (req, body, res) => {
				res.writeHead(500, { "Content-Type": "application/json" });
				res.end(JSON.stringify({ error: "upstream LLM timeout" }));
			},
		});
		process.env.FIRECLAW_BASE_URL = `http://127.0.0.1:${(server.address() as any).port}`;
		let threw = false;
		let msg = "";
		try { await searchWithFireclaw("q"); } catch (e: any) { threw = true; msg = e.message; }
		assert(threw, "threw on 500");
		assert(msg.includes("500"), `error mentions status (got "${msg}")`);
		await close(server);
	}

	// --- Test 4: empty content returns null ---
	{
		console.log("Test 4: empty content yields null (not a throw)");
		const server = await startMock({
			proxy: (req, body, res) => {
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(JSON.stringify({ content: "   ", metadata: {} }));
			},
		});
		process.env.FIRECLAW_BASE_URL = `http://127.0.0.1:${(server.address() as any).port}`;
		const result = await searchWithFireclaw("q");
		assert(result === null, "empty content -> null");
		await close(server);
	}

	// --- Test 5: availability off when unconfigured ---
	{
		console.log("Test 5: isFireclawAvailable() false without explicit base URL");
		delete process.env.FIRECLAW_BASE_URL;
		assert(isFireclawAvailable() === false, "availability false when not configured");
	}

	// --- Test 6: end-to-end through the search() dispatcher ---
	{
		console.log("Test 6: search({ provider: 'fireclaw' }) dispatches through gemini-search.ts");
		const server = await startMock({
			proxy: (req, body, res) => {
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(JSON.stringify({
					content: "Sanitized answer via dispatcher. [docs](https://fireclaw.app)",
					metadata: { trustTier: "trusted" },
				}));
			},
		});
		process.env.FIRECLAW_BASE_URL = `http://127.0.0.1:${(server.address() as any).port}`;
		const result = await search("what is fireclaw", { provider: "fireclaw" });
		assert(result.provider === "fireclaw", `provider attributed as fireclaw (got ${result.provider})`);
		assert(result.answer.includes("Sanitized answer via dispatcher"), "dispatcher answer flows through");
		assert(result.results.length === 1, `dispatcher extracted 1 source (got ${result.results.length})`);
		await close(server);
	}

	console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
	process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
