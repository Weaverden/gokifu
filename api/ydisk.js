/*
 * МИНИ-ПРОКСИ к Яндекс.Диску для ВЕБ-ВЕРСИИ Go Kifu (Vercel, edge-функция).
 *
 * ЗАЧЕМ. Браузер не может забрать файл с Яндекс.Диска сам:
 *   «Access to fetch at 'https://downloader.disk.yandex.ru/disk/…' from origin
 *    'https://weaverden.github.io' has been blocked by CORS policy: No
 *    'Access-Control-Allow-Origin' header is present on the requested resource.»
 * Ловушка: на ПРЕДВАРИТЕЛЬНЫЙ запрос (OPTIONS) тот же хост отвечает 204 и Allow-Origin: *.
 * Судить надо по ответу на сам запрос за файлом — там заголовка нет вовсе.
 *
 * ПОЧЕМУ НЕ CLOUDFLARE (замерено 28.08.2026 на сети заказчика, РФ). Тот же код на Workers
 * из командной строки отвечал за 280 мс, а из браузера то работал, то зависал:
 *   «net::ERR_QUIC_PROTOCOL_ERROR», подряд четыре запроса — 327, 124, 6923, 296 мс,
 *   а до того два зависания по 6 000 мс.
 * Cloudflare объявляет alt-svc: h3=":443" — браузер уходит на HTTP/3 (QUIC), а QUIC у
 * провайдера рвётся. Соседние площадки (vercel.app, netlify.app, github.io) HTTP/3 не
 * предлагают, браузер остаётся на TCP. Отсюда переезд.
 *
 * БЕЗОПАСНОСТЬ: пропускаем только адреса Яндекс.Диска и НЕ передаём заголовки входа —
 * иначе получился бы открытый пересыльщик чужих запросов и чужих токенов.
 */

export const config = { runtime: "edge" };

const ALLOW_ORIGIN = "*";
const ALLOWED_HOST = /(^|\.)(disk\.yandex\.(ru|net|com)|yandex\.net)$/i;

/**
 * Ответ браузеру: СВОИ заголовки, а не пересланные чужие.
 *
 * Площадка разжимает полученный ответ сама, поэтому Content-Encoding и Content-Length от
 * Яндекса пересылать нельзя: браузер поверит заголовку, попытается распаковать уже
 * распакованное и оборвёт загрузку. Берём только тип содержимого.
 */
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

export default async function handler(request) {
  if (request.method === "OPTIONS") return reply(204, null, null);

  const params = new URL(request.url).searchParams;

  // ЗАМЕР (временный, для разбора медленной синхронизации 28.08.2026):
  //   ?selftest=<байт> — отдать столько-то нулей: скорость ОТДАЧИ площадкой;
  //   ?echo=1 с телом  — прочитать тело и вернуть его размер: скорость ПРИЁМА.
  // Мелкие ответы пропускной способности не показывают: пробник в 20 байт приходил за 175 мс,
  // а настоящий обмен занял 21,7 с — надо понять, в какую сторону и на чём именно.
  const selftest = Number(params.get("selftest") || 0);
  if (selftest > 0) {
    return reply(200, new Uint8Array(Math.min(selftest, 20 * 1024 * 1024)), "application/octet-stream");
  }
  if (params.get("echo")) {
    const body = new Uint8Array(await request.arrayBuffer());
    return reply(200, "принято байт: " + body.length, "text/plain; charset=utf-8");
  }

  const target = params.get("url");
  if (!target) return reply(400, "нет параметра url", "text/plain; charset=utf-8");

  let host;
  try {
    host = new URL(target).hostname;
  } catch {
    return reply(400, "непонятный адрес", "text/plain; charset=utf-8");
  }
  if (!ALLOWED_HOST.test(host)) {
    return reply(403, "разрешён только Яндекс.Диск", "text/plain; charset=utf-8");
  }

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
    // Свой отказ С РАЗРЕШЕНИЯМИ лучше падения: у упавшего обработчика заголовков нет,
    // и приложение получает невнятный «сбой сети» вместо причины.
    return reply(502, "посредник не смог обратиться к Диску: " + e, "text/plain; charset=utf-8");
  }
}
