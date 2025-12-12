from __future__ import absolute_import, unicode_literals

import logging
import re
import urllib.parse

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.urls import reverse
from django.views.decorators.http import require_GET

from opaque_keys import InvalidKeyError
from opaque_keys.edx.keys import UsageKey

from seb_openedx.seb_keys_sources import get_config_by_course
from seb_openedx.permissions import get_enabled_permission_classes

LOG = logging.getLogger(__name__)


def _debug_seb_headers(request):
    """
    Вспомогательная функция: лог SEB-заголовков, чтобы видеть, что реально доходит.
    """
    meta = request.META
    seb_headers = {
        k: v
        for k, v in meta.items()
        if k.upper().startswith("HTTP_X_SAFEEXAMBROWSER")
        or k.upper().startswith("HTTP_SEB")
    }
    LOG.info("[SEB sequence_status] request.META SEB headers: %s", seb_headers)


@login_required
@require_GET
def sequence_status(request):
    """
    Проверка: этот sequential требует SEB или нет?
    GET /seb-openedx/api/sequence_status/?usage_key=block-v1:...

    Возвращает:
      { "blocked": true/false, "seb_link": "seb://..." | null }
    """
    usage_key_string = request.GET.get("usage_key")
    if not usage_key_string:
        return JsonResponse({"blocked": False, "reason": "missing_usage_key"})

    try:
        usage_key = UsageKey.from_string(usage_key_string)
        course_key = usage_key.course_key
    except InvalidKeyError:
        LOG.warning(
            "[SEB sequence_status] InvalidKeyError for usage_key_string=%s",
            usage_key_string,
        )
        return JsonResponse(
            {
                "blocked": False,
                "reason": "invalid_usage_key",
                "usage_key": usage_key_string,
            }
        )

    config = get_config_by_course(course_key)
    blacklist_sequences = config.get("BLACKLIST_SEQUENCES", [])

    block_id_match = re.search(r"block@([^/?]+)", usage_key_string)
    block_id = block_id_match.group(1) if block_id_match else None

    LOG.info(
        "[SEB sequence_status] user=%s course=%s usage=%s block_id=%s blacklist=%s",
        request.user.username,
        course_key,
        usage_key_string,
        block_id,
        blacklist_sequences,
    )

    # Если этот sequential не в чёрном списке — SEB не нужен
    if not block_id or block_id not in blacklist_sequences:
        LOG.info("[SEB sequence_status] block_id not in blacklist -> blocked=False")
        return JsonResponse({"blocked": False})

    # --- НОВОЕ: если это запрос из SEB — сразу РАЗБЛОКИРУЕМ ---
    # if _is_seb_request(request):
    #     LOG.info(
    #         "[SEB sequence_status] _is_seb_request=True, allow access (blocked=False)"
    #     )
    #     return JsonResponse({"blocked": False})

    # --- ДАЛЬШЕ: sequential в BLACKLIST_SEQUENCES, обычный браузер, смотрим права ---

    access_denied = True  # по умолчанию запрещаем
    masquerade = None

    for perm_cls in get_enabled_permission_classes(course_key):
        perm = perm_cls()
        # try:
        ok = perm.check(request, course_key, masquerade)
        LOG.warning("!!!!!!!!!!!!!!!!!!!!!!")
        LOG.warning("[SEB sequence_status] = %s", ok)
        LOG.info(
            "[SEB sequence_status] permission %s.check -> %s",
            perm_cls.__name__,
            ok,
        )
        # Семантика как в middleware: если ХОТЬ ОДНО разрешение прошло — доступ открыт
        if ok:
            access_denied = False
            break
        # except Exception as e:
        #     LOG.exception(
        #         "[SEB sequence_status] permission %s.check raised: %s",
        #         perm_cls.__name__,
        #         e,
        #     )

    LOG.info(
        "[SEB sequence_status] DECISION: access_denied=%s => blocked=%s",
        access_denied,
        bool(access_denied),
    )

    # Если хоть одно разрешение пропустило (для обычного браузера этого не будет) — не блокируем
    if not access_denied:
        LOG.info(
            "[SEB sequence_status] access allowed for user=%s course=%s usage=%s",
            request.user.username,
            course_key,
            usage_key_string,
        )
        return JsonResponse({"blocked": False})

    # Иначе блокируем и строим seb:// ссылку
    try:
        url = reverse(
            "jump_to",
            kwargs=dict(course_id=str(course_key), location=str(usage_key_string)),
        )
        parsed_url = urllib.parse.urlparse(url)
        seb_url = parsed_url._replace(scheme="seb", netloc=request.get_host())
        seb_link = urllib.parse.urlunparse(seb_url)
    except Exception as e:
        LOG.error("[SEB sequence_status] failed to build seb_link: %s", e)
        seb_link = None

    LOG.info(
        "[SEB sequence_status] BLOCKED user=%s course=%s usage=%s seb_link=%s",
        request.user.username,
        course_key,
        usage_key_string,
        seb_link,
    )

    return JsonResponse(
        {
            "blocked": True,
            "seb_link": seb_link,
        }
    )


def _is_seb_request(request):
    """
    Грубое, но кросс-платформенное определение SEB:
      - смотрим спецзаголовки X-SafeExamBrowser-*
      - или наличие 'SEB/' в User-Agent.
    """
    meta = request.META

    seb_headers = {
        k: v
        for k, v in meta.items()
        if k.upper().startswith("HTTP_X_SAFEEXAMBROWSER")
        or k.upper().startswith("HTTP_SEB")
    }

    ua = meta.get("HTTP_USER_AGENT", "") or ""

    is_seb_ua = "SEB/" in ua or "Safe Exam Browser" in ua or "SafeExamBrowser" in ua

    LOG.info(
        "[SEB sequence_status] _is_seb_request: headers=%s, user_agent=%s, is_seb_ua=%s",
        seb_headers,
        ua,
        is_seb_ua,
    )

    return bool(seb_headers) or is_seb_ua
