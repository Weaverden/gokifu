/*
 * МИНИ-ПРОКСИ к Яндекс.Диску для ВЕБ-ВЕРСИИ Go Kifu — вариант для Netlify (пограничная функция).
 *
 * Зачем посредник: браузер не может забрать файл с Яндекс.Диска сам — на запрос за содержимым
 * нет заголовка `Access-Control-Allow-Origin`, ответ `403`. Телефона и ПК это не касается.
 *
 * Зачем ТРЕТЬЯ площадка (замеры из браузера на сети заказчика, РФ, 28.08.2026):
 *   Cloudflare Workers — 420 байт/с на объёме, плюс зависания QUIC; отключить HTTP/3 нельзя,
 *                        Cloudflare перебивает заголовок `Alt-Svc` своим;
 *   Vercel             — стабильно, но 0,2 МБ/с: архив библиотеки (~4 МБ) уходил 21,7 секунды;
 *   GitHub Pages       — 9–11 МБ/с (для сравнения; проксировать не умеет).
 * Netlify проверяется на том же замере: `?selftest=<байт>`.
 *
 * БЕЗОПАСНОСТЬ: пропускаем только адреса Яндекс.Диска и НЕ передаём заголовки входа.
 */

const ALLOW_ORIGIN = "*";
const ALLOWED_HOST = /(^|\.)(disk\.yandex\.(ru|net|com)|yandex\.net)$/i;

function reply(status, body, contentType) {
  const h = new Headers();
  if (contentType) h.set("Content-Type", contentType);
  h.set("Access-Control-Allow-Origin", ALLOW_ORIGIN);
  h.set("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS");
  h.set("Access-Control-Allow-Headers", "Content-Type");
  h.set("Access-Control-Max-Age", "86400");
  const empty = status === 204 || status === 304;
  return new Response(empty ? null : body, { status, headers: h });
}

export default async (request) => {
  if (request.method === "OPTIONS") return reply(204, null, null);

  const params = new URL(request.url).searchParams;

  // Замер пропускной способности: мелкие ответы её не показывают (Vercel отдавал пробник
  // за 175 мс и при этом 0,2 МБ/с на объёме).
  const selftest = Number(params.get("selftest") || 0);
  if (selftest > 0) {
    return reply(200, new Uint8Array(Math.min(selftest, 20 * 1024 * 1024)), "application/octet-stream");
  }

  const target = params.get("url");
  if (!target) return reply(400, "нет параметра url", "text/plain; charset=utf-8");

  let host;
  try { host = new URL(target).hostname; } catch { return reply(400, "непонятный адрес", "text/plain; charset=utf-8"); }
  if (!ALLOWED_HOST.test(host)) return reply(403, "разрешён только Яндекс.Диск", "text/plain; charset=utf-8");

  const headers = new Headers();
  const type = request.headers.get("Content-Type");
  if (type) headers.set("Content-Type", type);

  try {
    const answer = await fetch(target, {
      method: request.method,
      headers,
      body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
    });
    return reply(answer.status, answer.body, answer.headers.get("Content-Type"));
  } catch (e) {
    return reply(502, "посредник не смог обратиться к Диску: " + e, "text/plain; charset=utf-8");
  }
};

export const config = { path: "/api/ydisk" };
