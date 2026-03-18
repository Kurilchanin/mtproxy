/**
 * MTProxy API — Cloudflare Worker
 *
 * Endpoints:
 *   GET  /                  — SSR HTML-страница с прокси (RU/EN)
 *   GET  /api/fetch-proxies — проксирует запрос к mtpro.xyz (обход блокировки)
 *   POST /api/proxies       — принимает проверенные прокси от сервера (с auth)
 *   GET  /api/proxies       — отдаёт прокси (для gecko-vpn-app)
 */

const MTPRO_API = 'https://mtpro.xyz/api/?type=mtprotoS';
const MTPRO_HEADERS = {
	'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
	'Referer': 'https://mtpro.xyz/mtproto',
	'Accept': 'application/json, text/plain, */*',
	'Origin': 'https://mtpro.xyz',
};

const CANONICAL_URL = 'https://mtproxy.geckocloud.workers.dev';

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

		if (path === '/' && request.method === 'GET') {
			return handlePage(request, url, env);
		}

		if (path === '/robots.txt') {
			return new Response(`User-agent: *\nAllow: /\nSitemap: ${CANONICAL_URL}/sitemap.xml\n`, {
				headers: { 'Content-Type': 'text/plain' },
			});
		}

		if (path === '/sitemap.xml') {
			const now = new Date().toISOString().split('T')[0];
			return new Response(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xhtml="http://www.w3.org/1999/xhtml">
  <url>
    <loc>${CANONICAL_URL}/</loc>
    <xhtml:link rel="alternate" hreflang="ru" href="${CANONICAL_URL}/?lang=ru"/>
    <xhtml:link rel="alternate" hreflang="en" href="${CANONICAL_URL}/?lang=en"/>
    <xhtml:link rel="alternate" hreflang="fa" href="${CANONICAL_URL}/?lang=fa"/>
    <lastmod>${now}</lastmod>
    <changefreq>hourly</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>`, {
				headers: { 'Content-Type': 'application/xml' },
			});
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

// ——— i18n ———
const i18n = {
	ru: {
		title: 'MTProto Proxy — Бесплатные рабочие прокси для Telegram',
		metaDesc: 'Список бесплатных MTProto прокси для Telegram. FakeTLS, обход блокировок, автоматическая проверка 24/7.',
		heading: 'MTProto Proxy',
		subtitle: 'Автоматическая проверка 24/7. Показаны только работающие прокси.',
		banner: 'Все прокси проверены реальными криптографическими TLS handshake-ами — вы видите только те, которые <strong>действительно работают</strong> прямо сейчас.',
		aliveLabel: 'Рабочих прокси:',
		updatedLabel: 'Обновлено:',
		thHost: 'Host',
		thPort: 'Port',
		thCountry: 'Страна',
		thConnect: 'Подключить',
		empty: 'Прокси загружаются... Первая проверка занимает ~2 минуты.',
		allCountries: 'Все страны',
		searchPlaceholder: 'Поиск по хосту...',
		langSwitch: 'EN',
		langSwitchTo: 'en',
		ogLocale: 'ru_RU',
		faqTitle: 'Часто задаваемые вопросы',
		faq: [
			{
				q: 'Что такое MTProto прокси?',
				a: 'MTProto прокси — это специальный тип прокси-сервера, разработанный для Telegram. В отличие от обычных SOCKS5 или HTTP прокси, MTProto прокси работают на уровне протокола Telegram и обеспечивают шифрованное соединение, которое не отличается от обычного HTTPS-трафика.',
			},
			{
				q: 'Что значит FakeTLS?',
				a: 'FakeTLS (секреты начинаются на ee) — это самый современный тип MTProto прокси. Трафик маскируется под обычное TLS-соединение с реальным доменом, что делает его неотличимым от обычного веб-трафика для систем глубокой инспекции пакетов (DPI).',
			},
			{
				q: 'Как проверяются прокси?',
				a: 'Каждый прокси проверяется реальным криптографическим TLS handshake. Мы отправляем TLS Client Hello с HMAC-SHA256 подписью — точно так же, как это делает Telegram. Если прокси отвечает корректным Server Hello — он работает.',
			},
			{
				q: 'Как подключиться к прокси?',
				a: 'Нажмите кнопку «TG» рядом с нужным прокси — откроется Telegram с предложением подключиться. Либо нажмите «Web» для подключения через браузер. Прокси бесплатные и не требуют регистрации.',
			},
			{
				q: 'Как часто обновляется список?',
				a: 'Список обновляется автоматически каждые 10 минут. Прокси сканируются, фильтруются и проверяются криптографическими handshake-ами 24/7. Вы видите только те прокси, которые работают прямо сейчас.',
			},
		],
		footerText: 'Бесплатные MTProto прокси для Telegram. Автоматическая проверка 24/7.',
	},
	en: {
		title: 'MTProto Proxy — Free Working Proxies for Telegram',
		metaDesc: 'List of free MTProto proxies for Telegram. FakeTLS, bypass blocks, automatic 24/7 checking.',
		heading: 'MTProto Proxy',
		subtitle: 'Automatic 24/7 verification. Only working proxies shown.',
		banner: 'All proxies are verified with real cryptographic TLS handshakes — you only see those that <strong>actually work</strong> right now.',
		aliveLabel: 'Working proxies:',
		updatedLabel: 'Updated:',
		thHost: 'Host',
		thPort: 'Port',
		thCountry: 'Country',
		thConnect: 'Connect',
		empty: 'Loading proxies... First check takes ~2 minutes.',
		allCountries: 'All countries',
		searchPlaceholder: 'Search by host...',
		langSwitch: 'RU',
		langSwitchTo: 'ru',
		ogLocale: 'en_US',
		faqTitle: 'Frequently Asked Questions',
		faq: [
			{
				q: 'What is an MTProto proxy?',
				a: 'MTProto proxy is a special type of proxy server designed for Telegram. Unlike regular SOCKS5 or HTTP proxies, MTProto proxies work at the Telegram protocol level and provide an encrypted connection that is indistinguishable from regular HTTPS traffic.',
			},
			{
				q: 'What does FakeTLS mean?',
				a: 'FakeTLS (secrets starting with ee) is the most advanced type of MTProto proxy. Traffic is disguised as a regular TLS connection to a real domain, making it indistinguishable from normal web traffic for deep packet inspection (DPI) systems.',
			},
			{
				q: 'How are proxies verified?',
				a: 'Each proxy is verified with a real cryptographic TLS handshake. We send a TLS Client Hello with an HMAC-SHA256 signature — exactly as Telegram does. If the proxy responds with a correct Server Hello — it works.',
			},
			{
				q: 'How do I connect to a proxy?',
				a: 'Click the "TG" button next to a proxy — Telegram will open with a connection prompt. Or click "Web" to connect via browser. All proxies are free and require no registration.',
			},
			{
				q: 'How often is the list updated?',
				a: 'The list is updated automatically every 10 minutes. Proxies are scanned, filtered, and verified with cryptographic handshakes 24/7. You only see proxies that are working right now.',
			},
		],
		footerText: 'Free MTProto proxies for Telegram. Automatic verification 24/7.',
	},
	fa: {
		title: 'MTProto Proxy — پراکسی رایگان تلگرام',
		metaDesc: 'لیست پراکسی‌های رایگان MTProto برای تلگرام. FakeTLS، دور زدن فیلترینگ، بررسی خودکار ۲۴/۷.',
		heading: 'MTProto Proxy',
		subtitle: 'بررسی خودکار ۲۴/۷. فقط پراکسی‌های فعال نمایش داده می‌شوند.',
		banner: 'تمام پراکسی‌ها با handshake‌های رمزنگاری واقعی TLS تایید شده‌اند — شما فقط آن‌هایی را می‌بینید که <strong>واقعاً الان کار می‌کنند</strong>.',
		aliveLabel: 'پراکسی فعال:',
		updatedLabel: 'به‌روزرسانی:',
		thHost: 'هاست',
		thPort: 'پورت',
		thCountry: 'کشور',
		thConnect: 'اتصال',
		empty: 'در حال بارگذاری پراکسی‌ها... بررسی اول حدود ۲ دقیقه طول می‌کشد.',
		allCountries: 'همه کشورها',
		searchPlaceholder: 'جستجو بر اساس هاست...',
		ogLocale: 'fa_IR',
		faqTitle: 'سوالات متداول',
		faq: [
			{
				q: 'پراکسی MTProto چیست؟',
				a: 'پراکسی MTProto نوع خاصی از سرور پراکسی است که برای تلگرام طراحی شده. برخلاف پراکسی‌های معمولی SOCKS5 یا HTTP، پراکسی‌های MTProto در سطح پروتکل تلگرام کار می‌کنند و اتصال رمزنگاری شده‌ای ارائه می‌دهند که از ترافیک معمولی HTTPS قابل تشخیص نیست.',
			},
			{
				q: 'FakeTLS چیست؟',
				a: 'FakeTLS (رمزهایی که با ee شروع می‌شوند) پیشرفته‌ترین نوع پراکسی MTProto است. ترافیک به عنوان اتصال TLS معمولی به یک دامنه واقعی پنهان می‌شود و برای سیستم‌های بازرسی عمیق بسته (DPI) از ترافیک وب عادی قابل تشخیص نیست.',
			},
			{
				q: 'پراکسی‌ها چگونه تایید می‌شوند؟',
				a: 'هر پراکسی با یک handshake رمزنگاری واقعی TLS تایید می‌شود. ما یک TLS Client Hello با امضای HMAC-SHA256 ارسال می‌کنیم — دقیقاً مانند تلگرام. اگر پراکسی با Server Hello صحیح پاسخ دهد — کار می‌کند.',
			},
			{
				q: 'چگونه به پراکسی متصل شوم؟',
				a: 'روی دکمه «TG» کنار پراکسی مورد نظر کلیک کنید — تلگرام با پیشنهاد اتصال باز می‌شود. یا روی «Web» کلیک کنید تا از طریق مرورگر متصل شوید. همه پراکسی‌ها رایگان هستند و نیازی به ثبت‌نام ندارند.',
			},
			{
				q: 'لیست هر چند وقت به‌روز می‌شود؟',
				a: 'لیست هر ۱۰ دقیقه به‌صورت خودکار به‌روز می‌شود. پراکسی‌ها اسکن، فیلتر و با handshake‌های رمزنگاری ۲۴/۷ تایید می‌شوند. شما فقط پراکسی‌هایی را می‌بینید که الان کار می‌کنند.',
			},
		],
		footerText: 'پراکسی‌های رایگان MTProto برای تلگرام. تایید خودکار ۲۴/۷.',
	},
};

const SUPPORTED_LANGS = ['ru', 'en', 'fa'];

function detectLang(request, url) {
	const param = url.searchParams.get('lang');
	if (SUPPORTED_LANGS.includes(param)) return param;

	// CF-IPCountry — Cloudflare автоматически добавляет код страны
	const country = (request.headers.get('CF-IPCountry') || '').toUpperCase();
	if (country === 'RU' || country === 'BY' || country === 'KZ' || country === 'UA') return 'ru';
	if (country === 'IR') return 'fa';

	// Accept-Language fallback
	const accept = request.headers.get('Accept-Language') || '';
	if (accept.match(/^ru/i)) return 'ru';
	if (accept.match(/^fa/i)) return 'fa';

	return 'en';
}

function countryToFlag(cc) {
	if (!cc || cc.length !== 2) return '';
	return [...cc.toUpperCase()].map(c => `&#${0x1F1E6 + c.charCodeAt(0) - 65};`).join('');
}

function escapeHtml(s) {
	return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

async function handlePage(request, url, env) {
	const lang = detectLang(request, url);
	const t = i18n[lang];

	// Read proxies from KV
	const raw = await env.PROXIES.get('proxies');
	const updatedAt = await env.PROXIES.get('updated_at');
	const proxies = raw ? JSON.parse(raw) : [];

	const timeLocale = { ru: 'ru-RU', en: 'en-US', fa: 'fa-IR' }[lang];
	const updatedStr = updatedAt ? new Date(updatedAt).toLocaleTimeString(timeLocale, { hour: '2-digit', minute: '2-digit' }) : '—';

	// Build proxy table rows (SSR)
	let rows = '';
	if (proxies.length === 0) {
		rows = `<tr><td colspan="5" class="empty">${t.empty}</td></tr>`;
	} else {
		rows = proxies.map((p, i) => {
			const flag = countryToFlag(p.country);
			const host = escapeHtml(p.host);
			const port = escapeHtml(p.port);
			const secret = escapeHtml(p.secret);
			const tgLink = `tg://proxy?server=${host}&amp;port=${port}&amp;secret=${secret}`;
			return `<tr>
				<td><span class="status-dot"></span>${i + 1}</td>
				<td class="host-cell" title="${host}">${host}</td>
				<td>${port}</td>
				<td>${flag} ${escapeHtml(p.country || '??')}</td>
				<td><a href="${tgLink}" class="tg-link">${t.thConnect}</a></td>
			</tr>`;
		}).join('');
	}

	const isRtl = lang === 'fa';
	const langLinks = SUPPORTED_LANGS.filter(l => l !== lang).map(l => {
		const label = { ru: 'RU', en: 'EN', fa: 'FA' }[l];
		return `<a href="?lang=${l}" class="lang-switch" rel="alternate" hreflang="${l}">${label}</a>`;
	}).join(' ');

	// Build country options for filter
	const countries = [...new Set(proxies.map(p => p.country).filter(Boolean))].sort();
	const countryOptions = countries.map(cc => {
		const flag = countryToFlag(cc);
		return `<option value="${escapeHtml(cc)}">${flag} ${escapeHtml(cc)}</option>`;
	}).join('');

	// JSON-LD structured data
	const jsonLd = {
		'@context': 'https://schema.org',
		'@graph': [
			{
				'@type': 'WebSite',
				name: 'MTProto Proxy',
				url: CANONICAL_URL,
				description: t.metaDesc,
				inLanguage: { ru: 'ru-RU', en: 'en-US', fa: 'fa-IR' }[lang],
			},
			{
				'@type': 'FAQPage',
				mainEntity: t.faq.map(f => ({
					'@type': 'Question',
					name: f.q,
					acceptedAnswer: { '@type': 'Answer', text: f.a },
				})),
			},
			{
				'@type': 'ItemList',
				name: t.heading,
				numberOfItems: proxies.length,
				itemListElement: proxies.slice(0, 10).map((p, i) => ({
					'@type': 'ListItem',
					position: i + 1,
					name: `MTProto Proxy ${p.host}:${p.port}`,
					description: `FakeTLS proxy, ${p.country || 'Unknown'}`,
				})),
			},
		],
	};

	// FAQ HTML
	const faqHtml = t.faq.map(f => `
		<details>
			<summary>${escapeHtml(f.q)}</summary>
			<p>${escapeHtml(f.a)}</p>
		</details>`).join('');

	const keywordsByLang = {
		ru: 'прокси телеграм, бесплатные прокси, обход блокировок, мтпрото прокси, прокси для телеграма, рабочие прокси',
		en: 'mtproto proxy list, telegram proxy server, bypass blocks, working proxies, proxy for telegram, free mtproto',
		fa: 'پراکسی تلگرام, پراکسی رایگان, دور زدن فیلترینگ, پراکسی MTProto, فیلترشکن تلگرام, پروکسی تلگرام',
	};

	const html = `<!DOCTYPE html>
<html lang="${lang}"${isRtl ? ' dir="rtl"' : ''}>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${t.title}</title>
<meta name="description" content="${escapeHtml(t.metaDesc)}">
<link rel="canonical" href="${CANONICAL_URL}/?lang=${lang}">
<link rel="alternate" hreflang="ru" href="${CANONICAL_URL}/?lang=ru">
<link rel="alternate" hreflang="en" href="${CANONICAL_URL}/?lang=en">
<link rel="alternate" hreflang="fa" href="${CANONICAL_URL}/?lang=fa">
<link rel="alternate" hreflang="x-default" href="${CANONICAL_URL}/">
<meta property="og:title" content="${escapeHtml(t.title)}">
<meta property="og:description" content="${escapeHtml(t.metaDesc)}">
<meta property="og:type" content="website">
<meta property="og:url" content="${CANONICAL_URL}/?lang=${lang}">
<meta property="og:locale" content="${t.ogLocale}">
<meta property="og:site_name" content="MTProto Proxy">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="${escapeHtml(t.title)}">
<meta name="twitter:description" content="${escapeHtml(t.metaDesc)}">
<meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large">
<meta name="keywords" content="mtproto proxy, telegram proxy, free proxy, faketls, ${keywordsByLang[lang]}">
<script type="application/ld+json">${JSON.stringify(jsonLd)}</script>
<style>
  :root {
    --bg: #0f1117;
    --surface: #1a1d27;
    --border: #2a2d3a;
    --text: #e1e4ed;
    --muted: #8b8fa3;
    --accent: #6c63ff;
    --green: #22c55e;
    --red: #ef4444;
    --yellow: #eab308;
    --blue: #3b82f6;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace;
    font-size: 14px;
    line-height: 1.6;
  }
  .container { max-width: 1200px; margin: 0 auto; padding: 20px; }

  header {
    border-bottom: 1px solid var(--border);
    padding: 20px 0;
    margin-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  header h1 { font-size: 20px; font-weight: 600; }
  header p { color: var(--muted); font-size: 13px; margin-top: 4px; }

  .lang-switcher { display: flex; gap: 8px; }
  .lang-switch {
    background: var(--surface);
    color: var(--accent);
    border: 1px solid var(--border);
    padding: 6px 14px;
    border-radius: 6px;
    font-family: inherit;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    text-decoration: none;
  }
  .lang-switch:hover { border-color: var(--accent); }

  [dir="rtl"] { direction: rtl; text-align: right; }
  [dir="rtl"] thead th { text-align: right; }
  [dir="rtl"] .status-dot { margin-right: 0; margin-left: 6px; }

  .info-banner {
    background: rgba(59,130,246,0.08);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 20px;
    font-size: 13px;
    color: var(--text);
  }
  .info-banner strong { color: var(--green); }

  .info-bar {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    margin-bottom: 20px;
    padding: 14px 18px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
  }
  .info-item { display: flex; align-items: center; gap: 8px; }
  .info-label { color: var(--muted); font-size: 12px; }
  .info-value { font-weight: 600; }
  .info-value.green { color: var(--green); }
  .info-value.yellow { color: var(--yellow); }
  .info-value.blue { color: var(--blue); }

  .controls {
    display: flex;
    gap: 12px;
    margin-bottom: 20px;
    flex-wrap: wrap;
    align-items: center;
  }

  select, input {
    background: var(--surface);
    color: var(--text);
    border: 1px solid var(--border);
    padding: 8px 14px;
    border-radius: 6px;
    font-family: inherit;
    font-size: 13px;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  thead th {
    text-align: left;
    padding: 10px 12px;
    background: var(--surface);
    border-bottom: 2px solid var(--border);
    color: var(--muted);
    font-weight: 500;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
  }
  thead th:hover { color: var(--text); }
  tbody td {
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  tbody tr:hover { background: rgba(108, 99, 255, 0.05); }

  .status-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-right: 6px;
    background: var(--green);
    box-shadow: 0 0 6px var(--green);
  }

  .badge {
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 500;
  }
  .badge.faketls { background: rgba(59,130,246,0.15); color: var(--blue); }

  .tg-link {
    color: var(--accent);
    text-decoration: none;
    font-size: 12px;
  }
  .tg-link:hover { text-decoration: underline; }

  .host-cell {
    max-width: 200px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .empty {
    text-align: center;
    padding: 60px 20px;
    color: var(--muted);
  }

  .faq { margin-top: 40px; }
  .faq h2 { font-size: 18px; font-weight: 600; margin-bottom: 16px; }
  .faq details {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 8px;
    padding: 0;
  }
  .faq summary {
    padding: 14px 18px;
    cursor: pointer;
    font-weight: 500;
    font-size: 14px;
    list-style: none;
  }
  .faq summary::-webkit-details-marker { display: none; }
  .faq summary::before { content: '+ '; color: var(--accent); font-weight: 700; }
  .faq details[open] summary::before { content: '- '; }
  .faq details p {
    padding: 0 18px 14px;
    color: var(--muted);
    font-size: 13px;
    line-height: 1.7;
  }

  footer {
    margin-top: 40px;
    padding: 20px 0;
    border-top: 1px solid var(--border);
    text-align: center;
    color: var(--muted);
    font-size: 12px;
  }

  @media (max-width: 600px) {
    .container { padding: 10px; }
    table { font-size: 12px; }
    thead th, tbody td { padding: 6px 6px; }
    .host-cell { max-width: 110px; }
    header { flex-direction: column; gap: 12px; align-items: flex-start; }
    select, input { font-size: 12px; padding: 6px 10px; }
  }
</style>
</head>
<body>
<div class="container">
  <nav>
    <header>
      <div>
        <h1>${t.heading}</h1>
        <p>${t.subtitle}</p>
      </div>
      <div class="lang-switcher">${langLinks}</div>
    </header>
  </nav>

  <main>
    <section class="info-banner" aria-label="Verification info">
      ${t.banner}
    </section>

    <section class="info-bar" aria-label="Statistics">
      <div class="info-item">
        <span class="info-label">${t.aliveLabel}</span>
        <span class="info-value green">${proxies.length}</span>
      </div>
      <div class="info-item">
        <span class="info-label">${t.updatedLabel}</span>
        <span class="info-value">${updatedStr}</span>
      </div>
    </section>

    <section aria-label="Proxy list">
      <div class="controls">
        <select id="filterCountry" onchange="applyFilters()" aria-label="${t.allCountries}">
          <option value="">${t.allCountries}</option>
          ${countryOptions}
        </select>
        <input type="text" id="searchHost" placeholder="${t.searchPlaceholder}" oninput="applyFilters()" aria-label="${t.searchPlaceholder}">
      </div>

      <table>
        <thead>
          <tr>
            <th onclick="sortBy('index')">#</th>
            <th onclick="sortBy('host')">${t.thHost}</th>
            <th onclick="sortBy('port')">${t.thPort}</th>
            <th onclick="sortBy('country')">${t.thCountry}</th>
            <th>${t.thConnect}</th>
          </tr>
        </thead>
        <tbody id="proxyTable">${rows}</tbody>
      </table>
    </section>

    <section class="faq">
      <h2>${t.faqTitle}</h2>
      ${faqHtml}
    </section>
  </main>

  <footer>
    <p>${escapeHtml(t.footerText)}</p>
  </footer>
</div>

<script>
var proxies = ${JSON.stringify(proxies.map((p, i) => ({ ...p, index: i + 1 })))};
var displayProxies = proxies.slice();
var sortField = 'index';
var sortAsc = true;

function countryToFlag(cc) {
  if (!cc || cc.length !== 2) return '';
  return String.fromCodePoint(...[...cc.toUpperCase()].map(function(c) { return 0x1F1E6 + c.charCodeAt(0) - 65; }));
}

function applyFilters() {
  var cc = document.getElementById('filterCountry').value;
  var search = document.getElementById('searchHost').value.toLowerCase();
  displayProxies = proxies.filter(function(p) {
    if (cc && p.country !== cc) return false;
    if (search && !p.host.toLowerCase().includes(search)) return false;
    return true;
  });
  doSort();
  renderTable();
}

function sortBy(field) {
  if (sortField === field) { sortAsc = !sortAsc; }
  else { sortField = field; sortAsc = true; }
  doSort();
  renderTable();
}

function doSort() {
  displayProxies.sort(function(a, b) {
    var va = a[sortField], vb = b[sortField];
    if (va == null) va = '';
    if (vb == null) vb = '';
    if (typeof va === 'number' && typeof vb === 'number') return sortAsc ? va - vb : vb - va;
    return sortAsc ? String(va).localeCompare(String(vb)) : String(vb).localeCompare(String(va));
  });
}

function renderTable() {
  var tbody = document.getElementById('proxyTable');
  if (displayProxies.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty">${t.empty}</td></tr>';
    return;
  }
  tbody.innerHTML = displayProxies.map(function(p, i) {
    var flag = countryToFlag(p.country);
    var tgLink = 'tg://proxy?server=' + p.host + '&port=' + p.port + '&secret=' + p.secret;
    return '<tr>' +
      '<td><span class="status-dot"></span>' + (i + 1) + '</td>' +
      '<td class="host-cell" title="' + p.host + '">' + p.host + '</td>' +
      '<td>' + p.port + '</td>' +
      '<td>' + flag + ' ' + (p.country || '??') + '</td>' +
      '<td><a href="' + tgLink + '" class="tg-link">${t.thConnect}</a></td>' +
    '</tr>';
  }).join('');
}
</script>
</body>
</html>`;

	return new Response(html, {
		headers: {
			'Content-Type': 'text/html;charset=UTF-8',
			'Cache-Control': 'public, max-age=300',
		},
	});
}

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
	if (!resp.ok) {
		return new Response(JSON.stringify({ error: `mtpro.xyz returned ${resp.status}` }), {
			status: 502,
			headers: { 'Content-Type': 'application/json', ...corsHeaders },
		});
	}

	const all = await resp.json();
	// Фильтруем только FakeTLS (ee) и отдаём минимум полей
	const filtered = all
		.filter(p => p.secret && p.secret.toLowerCase().startsWith('ee'))
		.map(p => ({ host: p.host, port: p.port, secret: p.secret, country: p.country || '' }));

	return new Response(JSON.stringify(filtered), {
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
