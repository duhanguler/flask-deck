# ruff: noqa: RUF001
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone, tzinfo
from decimal import Decimal
from functools import lru_cache
from typing import Any, Protocol, runtime_checkable
from zoneinfo import ZoneInfo, available_timezones

from flask import g, has_request_context

LOCALE_SESSION_KEY = "_deck_locale"
TZ_SESSION_KEY = "_deck_tz"
_G_LOCALE_KEY = "_flask_deck_locale"
_G_TZ_KEY = "_flask_deck_tz"

RTL_LOCALES: frozenset[str] = frozenset({"ar", "he", "fa", "ur"})

CURATED_TIMEZONES: tuple[str, ...] = (
    "UTC",
    "Europe/Istanbul",
    "Europe/London",
    "Europe/Berlin",
    "America/New_York",
    "America/Chicago",
    "America/Los_Angeles",
    "Asia/Dubai",
    "Asia/Singapore",
    "Asia/Tokyo",
)

LOCALE_LABELS: dict[str, str] = {
    "en": "English (EN)",
    "tr": "Türkçe (TR)",
    "de": "Deutsch (DE)",
    "ar": "العربية (AR · RTL)",
}

_LOCALE_SEPARATORS: dict[str, tuple[str, str]] = {
    "en": (",", "."),
    "tr": (".", ","),
    "de": (".", ","),
    "ar": (",", "."),
}

BUILTIN_CATALOGS: dict[str, dict[str, str]] = {
    "en": {},
    "tr": {
        "Workspace": "Çalışma Alanı",
        "Dashboard": "Genel Bakış",
        "Governance": "Yönetişim",
        "Audit Ledger": "Denetim Kaydı",
        "RBAC Matrix": "RBAC Matrisi",
        "Schema ERD": "Şema ERD",
        "SQL Console": "SQL Konsolu",
        "Diagnostics": "Tanı Paneli",
        "Background Jobs": "Arka Plan İşleri",
        "2FA Security": "2FA Güvenlik",
        "Jump to model, record, action…": "Model, kayıt veya aksiyon ara…",
        "Filter models…": "Modelleri filtrele…",
        "Recent Events": "Son Olaylar",
        "All →": "Tümü →",
        "Keyboard Shortcuts": "Klavye Kısayolları",
        "Sign out": "Çıkış Yap",
        "Table": "Tablo",
        "Board": "Kanban",
        "Trash": "Çöp Kutusu",
        "Import": "İçe Aktar",
        "Export": "Dışa Aktar",
        "New": "Yeni",
        "Search": "Ara",
        "Reset": "Sıfırla",
        "Filters": "Filtreler",
        "Save View": "Görünümü Kaydet",
        "Columns": "Sütunlar",
        "Apply Filters": "Filtreleri Uygula",
        "Clear": "Temizle",
        "Actions": "İşlemler",
        "Edit": "Düzenle",
        "Delete": "Sil",
        "Restore": "Geri Yükle",
        "History": "Geçmiş",
        "Clone": "Kopyala",
        "Cancel": "İptal",
        "Confirm": "Onayla",
        "Save": "Kaydet",
        "Back": "Geri",
        "Prev": "Önceki",
        "Next": "Sonraki",
        "First": "İlk",
        "Preferences": "Tercihler",
        "Language": "Dil",
        "Timezone": "Saat Dilimi",
        "Apply": "Uygula",
        "matching records": "eşleşen kayıt",
        "Page Summary": "Sayfa Özeti",
        "Sign in": "Giriş Yap",
        "Add Condition": "Koşul Ekle",
        "Exit Impersonation": "Kimliğe Bürünmeyi Bitir",
    },
    "de": {
        "Workspace": "Arbeitsbereich",
        "Dashboard": "Übersicht",
        "Governance": "Governance",
        "Audit Ledger": "Audit-Protokoll",
        "RBAC Matrix": "RBAC-Matrix",
        "Schema ERD": "Schema-ERD",
        "SQL Console": "SQL-Konsole",
        "Diagnostics": "Diagnose",
        "Background Jobs": "Hintergrundjobs",
        "2FA Security": "2FA-Sicherheit",
        "Jump to model, record, action…": "Modell, Datensatz oder Aktion suchen…",
        "Filter models…": "Modelle filtern…",
        "Recent Events": "Letzte Ereignisse",
        "All →": "Alle →",
        "Keyboard Shortcuts": "Tastenkürzel",
        "Sign out": "Abmelden",
        "Table": "Tabelle",
        "Board": "Board",
        "Trash": "Papierkorb",
        "Import": "Importieren",
        "Export": "Exportieren",
        "New": "Neu",
        "Search": "Suchen",
        "Reset": "Zurücksetzen",
        "Filters": "Filter",
        "Save View": "Ansicht speichern",
        "Columns": "Spalten",
        "Apply Filters": "Filter anwenden",
        "Clear": "Leeren",
        "Actions": "Aktionen",
        "Edit": "Bearbeiten",
        "Delete": "Löschen",
        "Restore": "Wiederherstellen",
        "History": "Verlauf",
        "Clone": "Duplizieren",
        "Cancel": "Abbrechen",
        "Confirm": "Bestätigen",
        "Save": "Speichern",
        "Back": "Zurück",
        "Prev": "Zurück",
        "Next": "Weiter",
        "First": "Erste",
        "Preferences": "Einstellungen",
        "Language": "Sprache",
        "Timezone": "Zeitzone",
        "Apply": "Übernehmen",
        "matching records": "passende Einträge",
        "Page Summary": "Seitensumme",
        "Sign in": "Anmelden",
        "Add Condition": "Bedingung hinzufügen",
        "Exit Impersonation": "Impersonation beenden",
    },
    "ar": {
        "Workspace": "مساحة العمل",
        "Dashboard": "لوحة التحكم",
        "Governance": "الحوكمة",
        "Audit Ledger": "سجل التدقيق",
        "RBAC Matrix": "مصفوفة الصلاحيات",
        "Schema ERD": "مخطط الجداول",
        "SQL Console": "وحدة SQL",
        "Diagnostics": "التشخيص",
        "Background Jobs": "المهام الخلفية",
        "2FA Security": "التحقق الثنائي",
        "Jump to model, record, action…": "ابحث عن نموذج أو سجل أو إجراء…",
        "Filter models…": "تصفية النماذج…",
        "Recent Events": "أحدث الأحداث",
        "All →": "الكل ←",
        "Keyboard Shortcuts": "اختصارات لوحة المفاتيح",
        "Sign out": "تسجيل الخروج",
        "Table": "جدول",
        "Board": "لوحة كانبان",
        "Trash": "سلة المحذوفات",
        "Import": "استيراد",
        "Export": "تصدير",
        "New": "جديد",
        "Search": "بحث",
        "Reset": "إعادة تعيين",
        "Filters": "الفلاتر",
        "Save View": "حفظ العرض",
        "Columns": "الأعمدة",
        "Apply Filters": "تطبيق الفلاتر",
        "Clear": "مسح",
        "Actions": "إجراءات",
        "Edit": "تعديل",
        "Delete": "حذف",
        "Restore": "استعادة",
        "History": "السجل",
        "Clone": "نسخ",
        "Cancel": "إلغاء",
        "Confirm": "تأكيد",
        "Save": "حفظ",
        "Back": "رجوع",
        "Prev": "السابق",
        "Next": "التالي",
        "First": "الأول",
        "Preferences": "التفضيلات",
        "Language": "اللغة",
        "Timezone": "المنطقة الزمنية",
        "Apply": "تطبيق",
        "matching records": "سجل مطابق",
        "Page Summary": "ملخص الصفحة",
        "Sign in": "تسجيل الدخول",
        "Add Condition": "إضافة شرط",
        "Exit Impersonation": "إنهاء الانتحال",
    },
}


@runtime_checkable
class Translator(Protocol):
    """Minimal localization contract implemented by DictTranslator and BabelTranslator."""

    def translate(self, msgid: str, **params: Any) -> str:
        """Translate a UI message string for the active locale."""

    def get_locale(self) -> str:
        """Return active BCP-47 / ISO-639 locale code (e.g. 'en', 'tr', 'ar')."""

    def is_rtl(self, locale: str | None = None) -> bool:
        """Return True if the active or provided locale uses right-to-left script."""


def normalize_locale(locale: str | None, fallback: str = "en") -> str:
    if not locale:
        return fallback
    primary = locale.strip().replace("_", "-").split("-", 1)[0].lower()
    return primary or fallback


def is_rtl_locale(locale: str | None) -> bool:
    return normalize_locale(locale) in RTL_LOCALES


@lru_cache(maxsize=1)
def _cached_timezones() -> frozenset[str]:
    return frozenset(available_timezones())


def is_valid_timezone(tz_name: str | None) -> bool:
    if not tz_name or not isinstance(tz_name, str):
        return False
    clean = tz_name.strip()
    if clean == "UTC":
        return True
    return clean in _cached_timezones()


def set_request_locale_tz(locale: str, tz_name: str) -> None:
    if has_request_context():
        clean_tz = tz_name.strip() if isinstance(tz_name, str) else "UTC"
        setattr(g, _G_LOCALE_KEY, normalize_locale(locale))
        setattr(g, _G_TZ_KEY, clean_tz if is_valid_timezone(clean_tz) else "UTC")


def get_active_locale(default: str = "en") -> str:
    if has_request_context():
        val = getattr(g, _G_LOCALE_KEY, None)
        if isinstance(val, str) and val:
            return val
    return default


def get_active_timezone(default: str = "UTC") -> str:
    if has_request_context():
        val = getattr(g, _G_TZ_KEY, None)
        if isinstance(val, str) and is_valid_timezone(val):
            return val.strip()
    return default


def _resolve_tz(zone_name: str) -> tzinfo:
    if zone_name == "UTC":
        return timezone.utc
    try:
        return ZoneInfo(zone_name)
    except Exception:
        return timezone.utc


def to_user_timezone(dt: datetime, tz_name: str | None = None) -> datetime:
    """Convert an aware or naive-UTC datetime into the active user's ZoneInfo timezone."""
    aware = dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
    zone_name = (tz_name or get_active_timezone("UTC")).strip()
    return aware.astimezone(_resolve_tz(zone_name))


def from_user_timezone(
    dt: datetime,
    tz_name: str | None = None,
    *,
    store_naive_utc: bool = False,
) -> datetime:
    """Convert a naive user-entered datetime from active user timezone into UTC."""
    if dt.tzinfo is None:
        zone_name = (tz_name or get_active_timezone("UTC")).strip()
        aware = dt.replace(tzinfo=_resolve_tz(zone_name))
    else:
        aware = dt
    utc_dt = aware.astimezone(timezone.utc)
    return utc_dt.replace(tzinfo=None) if store_naive_utc else utc_dt


def format_locale_decimal(
    value: Decimal | float | int,
    *,
    decimals: int = 2,
    locale: str | None = None,
) -> str:
    """Format a number using locale-appropriate thousand and decimal separators."""
    loc = normalize_locale(locale or get_active_locale("en"))
    thousands_sep, dec_sep = _LOCALE_SEPARATORS.get(loc, (",", "."))
    sign = "-" if value < 0 else ""
    base = f"{abs(value):,.{decimals}f}"
    if thousands_sep != "," or dec_sep != ".":
        base = base.replace(",", "_").replace(".", dec_sep).replace("_", thousands_sep)
    return f"{sign}{base}"


class DictTranslator:
    """Zero-dependency built-in translator with curated EN, TR, DE, and AR (RTL) catalogs."""

    __slots__ = ("_catalogs", "_default_locale")

    def __init__(
        self,
        *,
        default_locale: str = "en",
        extra_catalogs: Mapping[str, Mapping[str, str]] | None = None,
    ) -> None:
        self._default_locale = normalize_locale(default_locale)
        self._catalogs: dict[str, dict[str, str]] = {
            code: dict(entries) for code, entries in BUILTIN_CATALOGS.items()
        }
        if extra_catalogs:
            for code, entries in extra_catalogs.items():
                norm = normalize_locale(code)
                self._catalogs.setdefault(norm, {}).update(entries)

    def get_locale(self) -> str:
        return get_active_locale(self._default_locale)

    def is_rtl(self, locale: str | None = None) -> bool:
        return is_rtl_locale(locale or self.get_locale())

    def translate(self, msgid: str, **params: Any) -> str:
        loc = self.get_locale()
        catalog = self._catalogs.get(loc, {})
        text = catalog.get(msgid, msgid)
        if params:
            try:
                return text.format(**params)
            except Exception:
                return text
        return text


class BabelTranslator:
    """Optional Flask-Babel adapter (requires `pip install 'flask-deck[babel]'`)."""

    __slots__ = ("_babel_module", "_fallback")

    def __init__(
        self,
        *,
        babel_module: Any | None = None,
        fallback_locale: str = "en",
    ) -> None:
        if babel_module is None:
            try:
                import flask_babel  # type: ignore[import-not-found]
            except ImportError as exc:
                raise RuntimeError(
                    "Flask-Babel is required for BabelTranslator. "
                    "Install with: pip install 'flask-deck[babel]'"
                ) from exc
            babel_module = flask_babel
        self._babel_module = babel_module
        self._fallback = DictTranslator(default_locale=fallback_locale)

    def get_locale(self) -> str:
        getter = getattr(self._babel_module, "get_locale", None)
        if callable(getter):
            loc = getter()
            if loc is not None:
                return normalize_locale(str(loc))
        return self._fallback.get_locale()

    def is_rtl(self, locale: str | None = None) -> bool:
        return is_rtl_locale(locale or self.get_locale())

    def translate(self, msgid: str, **params: Any) -> str:
        gettext_fn = getattr(self._babel_module, "gettext", None)
        if callable(gettext_fn):
            translated = str(gettext_fn(msgid, **params))
            if translated != msgid:
                return translated
        return self._fallback.translate(msgid, **params)
