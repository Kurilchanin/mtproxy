/**
 * MTProxy API — Cloudflare Worker
 *
 * KV key "proxies" → JSON array of working FakeTLS proxies (ping 50-500ms)
 *
 * Endpoints:
 *   POST /api/proxies  — принимает список от сервера (с auth токеном)
 *   GET  /api/proxies   — отдаёт топ-10 по пингу (для gecko-vpn-app)
 *   GET  /api/proxies?limit=N — отдаёт топ-N
 */

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		const path = url.pathname;

		// CORS headers
		const corsHeaders = {
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type, Authorization',
		};

		if (request.method === 'OPTIONS') {
			return new Response(null, { headers: corsHeaders });
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

async function handlePost(request, env, corsHeaders) {
	// Проверяем auth токен
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

	// Сохраняем в KV с TTL 15 минут (на случай если сервер перестанет обновлять)
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
	// Уже отсортированы по пингу, берём первые N
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
