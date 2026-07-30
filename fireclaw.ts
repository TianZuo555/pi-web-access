import { existsSync, readFileSync } from "node:fs";
import { activityMonitor } from "./activity.ts";
import type { SearchOptions, SearchResponse } from "./perplexity.ts";
import { getWebSearchConfigPath } from "./utils.ts";

/**
 * FireClaw search provider.
 *
 * FireClaw (https://github.com/raiph-ai/fireclaw) is an open-source security
 * proxy that runs a 4-stage sanitization pipeline (DNS blocklists, structural
 * sanitization, LLM fact extraction, output scanning) between an agent and the
 * web. This provider routes `web_search` requests through a running FireClaw
 * proxy instance so results are stripped of prompt-injection payloads before
 * they reach the agent's context window.
 *
 * Proxy API contract (dashboard/server.mjs):
 *   POST {baseUrl}/api/proxy
 *     Headers: Content-Type: application/json
 *              X-FireClaw-Action: search
 *              Authorization: Bearer {apiKey}   (optional, remote mode)
 *     Body:    { "query": string, "count": number }
 *   -> { "content": string, "metadata": { severity, detections, duration, cached, trustTier, ... } }
 *
 * Configure via web-search.json:
 *   {
 *     "fireclawBaseUrl": "http://localhost:8420",   // or FIRECLAW_BASE_URL env
 *     "fireclawApiKey": "$FIRECLAW_API_KEY"          // optional, remote mode only
 *   }
 */

const DEFAULT_BASE_URL = "http://localhost:8420";
const CONFIG_PATH = getWebSearchConfigPath();

interface WebSearchConfig {
	fireclawBaseUrl?: unknown;
	fireclawApiKey?: unknown;
}

interface FireclawMetadata {
	severity?: string;
	detections?: unknown;
	duration?: number;
	cached?: boolean;
	trustTier?: string;
	blocked?: boolean;
	enabled?: boolean;
}

interface FireclawSearchResponse {
	content?: string;
	metadata?: FireclawMetadata;
	error?: string;
}

export type FireclawSearchResult = SearchResponse | null;

export interface FireclawSearchOptions extends SearchOptions {
	includeContent?: boolean;
}

let cachedConfig: WebSearchConfig | null = null;

function loadConfig(): WebSearchConfig {
	if (cachedConfig) return cachedConfig;
	if (!existsSync(CONFIG_PATH)) {
		cachedConfig = {};
		return cachedConfig;
	}

	const raw = readFileSync(CONFIG_PATH, "utf-8");
	try {
		cachedConfig = JSON.parse(raw) as WebSearchConfig;
		return cachedConfig;
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		throw new Error(`Failed to parse ${CONFIG_PATH}: ${message}`);
	}
}

function normalizeString(value: unknown): string | null {
	if (typeof value !== "string") return null;
	const normalized = value.trim();
	return normalized.length > 0 ? normalized : null;
}

/** Explicitly configured base URL (env or config), excluding the default. */
function getConfiguredBaseUrl(): string | null {
	return normalizeString(process.env.FIRECLAW_BASE_URL) ?? normalizeString(loadConfig().fireclawBaseUrl);
}

/** Resolved base URL, falling back to the local default when actually called. */
function getBaseUrl(): string {
	return getConfiguredBaseUrl() ?? DEFAULT_BASE_URL;
}

function getApiKey(): string | null {
	return normalizeString(process.env.FIRECLAW_API_KEY) ?? normalizeString(loadConfig().fireclawApiKey);
}

function requestSignal(signal?: AbortSignal): AbortSignal {
	const timeout = AbortSignal.timeout(60000);
	return signal ? AbortSignal.any([signal, timeout]) : timeout;
}

/**
 * Extract markdown-style source links from sanitized content so the result is
 * attributed. FireClaw returns a single sanitized text blob; any `[label](url)`
 * links it preserves become clickable sources.
 */
function extractSourceUrls(content: string): SearchResponse["results"] {
	const results: SearchResponse["results"] = [];
	const seen = new Set<string>();
	const linkRegex = /\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g;
	for (const match of content.matchAll(linkRegex)) {
		const url = match[2];
		if (seen.has(url)) continue;
		seen.add(url);
		results.push({ title: match[1], url, snippet: "" });
	}
	return results;
}

/**
 * Whether FireClaw should be considered for the auto provider chain.
 *
 * FireClaw requires a running proxy, so we only opt in when a base URL is
 * explicitly configured (env or config). This keeps FireClaw out of the auto
 * rotation for users who haven't deployed a proxy, while an explicit
 * `provider: "fireclaw"` still works against the local default.
 */
export function isFireclawAvailable(): boolean {
	return !!getConfiguredBaseUrl();
}

export async function searchWithFireclaw(query: string, options: FireclawSearchOptions = {}): Promise<FireclawSearchResult> {
	const baseUrl = getBaseUrl();
	const apiKey = getApiKey();
	const count = options.numResults ?? 5;

	const activityId = activityMonitor.logStart({ type: "api", query });

	try {
		const response = await fetch(`${baseUrl}/api/proxy`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"X-FireClaw-Action": "search",
				...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
			},
			body: JSON.stringify({ query, count }),
			signal: requestSignal(options.signal),
		});

		if (!response.ok) {
			const errorText = await response.text();
			throw new Error(`FireClaw proxy error ${response.status}: ${errorText.slice(0, 300)}`);
		}

		const data = await response.json() as FireclawSearchResponse;
		activityMonitor.logComplete(activityId, response.status);

		if (data.error) {
			throw new Error(`FireClaw search error: ${data.error}`);
		}

		const content = typeof data.content === "string" ? data.content.trim() : "";
		if (!content) return null;

		return {
			answer: content,
			results: extractSourceUrls(content),
		};
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		if (message.toLowerCase().includes("abort")) {
			activityMonitor.logComplete(activityId, 0);
		} else {
			activityMonitor.logError(activityId, message);
		}
		throw err;
	}
}
