/**
 * MTProxy API — Cloudflare Worker
 *
 * Endpoints:
 *   GET  /api/fetch-proxies — проксирует запрос к mtpro.xyz (обход блокировки)
 *   POST /api/proxies       — принимает проверенные прокси от сервера (с auth)
 *   GET  /api/proxies       — отдаёт топ-10 по пингу (для gecko-vpn-app)
 */

const MTPRO_API = 'https://mtpro.xyz/api/?type=mtprotoS';
const MTPRO_HEADERS = {
	'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
	'Referer': 'https://mtpro.xyz/mtproto',
	'Accept': 'application/json, text/plain, */*',
	'Origin': 'https://mtpro.xyz',
};

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		const path = url.pathname;

		const corsHeaders = {
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type, Authorization',
		};

		if (request.method === 'OPTIONS') {
			return new Response(null, { headers: corsHeaders });
		}

		if (path === '/api/fetch-proxies' && request.method === 'GET') {
			return handleFetchProxies(request, env, corsHeaders);
		}

		if (path === '/api/proxies') {
			if (request.method === 'POST') {
				return handlePost(request, env, corsHeaders);
			}
			if (request.method === 'GET') {
				return handleGet(url, env, corsHeaders);
			}
		}

		return new Response('Not found', { status: 404 });
	},
};

async function handleFetchProxies(request, env, corsHeaders) {
	// Auth check
	const auth = request.headers.get('Authorization');
	if (!auth || auth !== `Bearer ${env.API_TOKEN}`) {
		return new Response(JSON.stringify({ error: 'unauthorized' }), {
			status: 401,
			headers: { 'Content-Type': 'application/json', ...corsHeaders },
		});
	}

	// Проксируем запрос к mtpro.xyz через CF (нероссийский IP)
	const resp = await fetch(MTPRO_API, { headers: MTPRO_HEADERS });
	const data = await resp.text();

	return new Response(data, {
		status: resp.status,
		headers: { 'Content-Type': 'application/json', ...corsHeaders },
	});
}

async function handlePost(request, env, corsHeaders) {
	const auth = request.headers.get('Authorization');
	if (!auth || auth !== `Bearer ${env.API_TOKEN}`) {
		return new Response(JSON.stringify({ error: 'unauthorized' }), {
			status: 401,
			headers: { 'Content-Type': 'application/json', ...corsHeaders },
		});
	}

	const body = await request.json();
	const proxies = body.proxies;

	if (!Array.isArray(proxies)) {
		return new Response(JSON.stringify({ error: 'proxies must be an array' }), {
			status: 400,
			headers: { 'Content-Type': 'application/json', ...corsHeaders },
		});
	}

	await env.PROXIES.put('proxies', JSON.stringify(proxies), { expirationTtl: 900 });
	await env.PROXIES.put('updated_at', new Date().toISOString(), { expirationTtl: 900 });

	return new Response(JSON.stringify({ ok: true, count: proxies.length }), {
		headers: { 'Content-Type': 'application/json', ...corsHeaders },
	});
}

async function handleGet(url, env, corsHeaders) {
	const limit = parseInt(url.searchParams.get('limit') || '10', 10);

	const raw = await env.PROXIES.get('proxies');
	if (!raw) {
		return new Response(JSON.stringify({ proxies: [], count: 0, updated_at: null }), {
			headers: { 'Content-Type': 'application/json', ...corsHeaders },
		});
	}

	const all = JSON.parse(raw);
	const proxies = all.slice(0, limit);
	const updatedAt = await env.PROXIES.get('updated_at');

	return new Response(JSON.stringify({
		proxies,
		count: proxies.length,
		total: all.length,
		updated_at: updatedAt,
	}), {
		headers: { 'Content-Type': 'application/json', ...corsHeaders },
	});
}
