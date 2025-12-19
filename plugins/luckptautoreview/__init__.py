import json
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, parse_qs

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from bs4 import BeautifulSoup

from app.core.config import settings
from app.helper.sites import SitesHelper
from app.log import logger
from app.plugins import _PluginBase
from app.schemas import NotificationType
from app.utils.http import RequestUtils


# ----------------------------
# 常量 / 默认配置
# ----------------------------
LEVEL_ORDER = [
    "Peasant",
    "User",
    "Power User",
    "Elite User",
    "Crazy User",
    "Insane User",
    "Veteran User",
    "Extreme User",
    "Ultimate User",
    "Nexus Master",
    "贵宾 (VIP)",
    "养老族 (Retiree)",
    "发布员 (Uploader)",
    "总版主 (Moderator)",
    "管理员 (Administrator)",
    "维护开发员 (Sysop)",
    "主管 (Staff Leader)",
]

DEFAULT_LEVEL_ALIASES: Dict[str, str] = {
    "poweruser": "Power User",
    "pu": "Power User",
    "eliteuser": "Elite User",
    "crazyuser": "Crazy User",
    "insaneuser": "Insane User",
    "veteranuser": "Veteran User",
    "extremeuser": "Extreme User",
    "ultimateuser": "Ultimate User",
    "nexusmaster": "Nexus Master",
    "波斯猫": "Peasant",
    "伯曼猫": "User",
    "加菲猫": "Power User",
    "布偶猫": "Elite User",
    "雪鞋猫": "Crazy User",
    "暹罗猫": "Insane User",
    "安哥拉猫": "Veteran User",
    "孟加拉猫": "Extreme User",
    "山东狮子猫": "Ultimate User",
    "四川简州猫": "Nexus Master",
    "挪威森林猫": "贵宾 (VIP)",
    "挪威森林猫 vip": "贵宾 (VIP)",
    "美国短毛猫": "养老族 (Retiree)",
    "英國短毛貓": "发布员 (Uploader)",
    "英国短毛猫": "发布员 (Uploader)",
    "俄罗斯蓝猫": "总版主 (Moderator)",
    "俄羅斯藍貓": "总版主 (Moderator)",
    "中华田园猫": "管理员 (Administrator)",
    "蘇格蘭摺耳貓": "维护开发员 (Sysop)",
    "苏格兰折耳猫": "维护开发员 (Sysop)",
    "阿比西尼亚猫": "主管 (Staff Leader)",
    "阿比西尼亞貓": "主管 (Staff Leader)",
    "游魂": "Peasant",
    "临时演员": "User",
    "跑龙套": "Power User",
    "配角": "Elite User",
    "主演": "Crazy User",
    "领衔主演": "Insane User",
    "明星": "Veteran User",
    "国际大腕": "Extreme User",
    "影帝": "Ultimate User",
    "终身影帝": "Nexus Master",
    "vip": "贵宾 (VIP)",
    "v i p": "贵宾 (VIP)",
    "貴賓": "贵宾 (VIP)",
    "总版主": "总版主 (Moderator)",
    "總版主": "总版主 (Moderator)",
    "管理员": "管理员 (Administrator)",
    "管理員": "管理员 (Administrator)",
    "系统管理员": "维护开发员 (Sysop)",
    "系統管理員": "维护开发员 (Sysop)",
    "版主": "总版主 (Moderator)",
    "版務": "总版主 (Moderator)",
    "发布员": "发布员 (Uploader)",
    "發布員": "发布员 (Uploader)",
    "养老族": "养老族 (Retiree)",
    "養老族": "养老族 (Retiree)",
    "吸血鬼": "Peasant",
    "惊蛰": "Peasant",
    "新人": "User",
    "萌动": "User",
    "易形": "Power User",
    "精英": "Elite User",
    "化蛹": "Elite User",
    "破茧": "Crazy User",
    "恋风": "Insane User",
    "翩跹": "Veteran User",
    "归尘": "Extreme User",
    "幻梦": "Ultimate User",
    "逍遥": "Nexus Master",
    "叛徒": "Peasant",
    "平民": "User",
    "正兵": "Power User",
    "军士": "Elite User",
    "副军校": "Crazy User",
    "正军校": "Insane User",
    "副参领": "Veteran User",
    "正参领": "Extreme User",
    "副都统": "Ultimate User",
    "大将军": "Nexus Master",
    "大师": "Extreme User",
    "神仙": "Ultimate User",
    "神王": "Nexus Master",
    "贵宾": "贵宾 (VIP)",
    "荣誉会员": "贵宾 (VIP)",
    "荣誉": "贵宾 (VIP)",
    "honor": "贵宾 (VIP)",
    "发布员": "发布员 (Uploader)",
    "保种员": "发布员 (Uploader)",
    "编辑员": "总版主 (Moderator)",
    "助理员": "总版主 (Moderator)",
    "维护开发员": "维护开发员 (Sysop)",
    "主管": "主管 (Staff Leader)",
    "站长": "管理员 (Administrator)",
    "庶民": "Peasant",
    "列兵": "User",
    "士官": "Power User",
    "尉官": "Elite User",
    "少校": "Crazy User",
    "中校": "Insane User",
    "上校": "Veteran User",
    "少将": "Extreme User",
    "中将": "Ultimate User",
    "上将": "Nexus Master",
    "救生圈": "Peasant",
    "澡盆": "User",
    "独木舟": "Power User",
    "竹筏": "Elite User",
    "赛艇": "Crazy User",
    "邮轮": "Insane User",
    "驱逐舰": "Veteran User",
    "巡洋舰": "Extreme User",
    "战列舰": "Ultimate User",
    "航空母舰": "Nexus Master",
    "爹": "贵宾 (VIP)",
    "救命恩人": "贵宾 (VIP)",
    "异教徒": "Peasant",
    "路人": "User",
    "御宅族": "Power User",
    "宅修士": "Elite User",
    "宅教士": "Crazy User",
    "宅传教士": "Insane User",
    "宅傳教士": "Insane User",
    "宅護法": "Veteran User",
    "宅护法": "Veteran User",
    "宅賢者": "Extreme User",
    "宅贤者": "Extreme User",
    "宅聖": "Ultimate User",
    "宅圣": "Ultimate User",
    "宅神": "Nexus Master",
    "福音組": "发布员 (Uploader)",
    "福音组": "发布员 (Uploader)",
    "现充": "贵宾 (VIP)",
    "現充": "贵宾 (VIP)",
    "fff团": "总版主 (Moderator)",
    "fff團": "总版主 (Moderator)",
    "执事": "管理员 (Administrator)",
    "執事": "管理员 (Administrator)",
    "司鐸": "管理员 (Administrator)",
    "司铎": "管理员 (Administrator)",
    "枢机": "维护开发员 (Sysop)",
    "樞機": "维护开发员 (Sysop)",
    "站宗": "主管 (Staff Leader)",
}

# 按优先级从高到低的关键词映射，用于模糊匹配等级。
LEVEL_KEYWORDS: List[Tuple[str, str]] = [
    ("神王", "Nexus Master"),
    ("nexus master", "Nexus Master"),
    ("逍遥", "Nexus Master"),
    ("大将军", "Nexus Master"),
    ("上将", "Nexus Master"),
    ("航空母舰", "Nexus Master"),
    ("宅神", "Nexus Master"),
    ("四川简州猫", "Nexus Master"),
    ("挪威森林猫 vip", "贵宾 (VIP)"),
    ("终身影帝", "Nexus Master"),
    ("神仙", "Ultimate User"),
    ("ultimate user", "Ultimate User"),
    ("山东狮子猫", "Ultimate User"),
    ("影帝", "Ultimate User"),
    ("幻梦", "Ultimate User"),
    ("副都统", "Ultimate User"),
    ("中将", "Ultimate User"),
    ("战列舰", "Ultimate User"),
    ("宅圣", "Ultimate User"),
    ("宅聖", "Ultimate User"),
    ("大师", "Extreme User"),
    ("extreme user", "Extreme User"),
    ("孟加拉猫", "Extreme User"),
    ("归尘", "Extreme User"),
    ("正参领", "Extreme User"),
    ("少将", "Extreme User"),
    ("巡洋舰", "Extreme User"),
    ("宅贤者", "Extreme User"),
    ("宅賢者", "Extreme User"),
    ("国际大腕", "Extreme User"),
    ("veteran", "Veteran User"),
    ("veteran user", "Veteran User"),
    ("安哥拉猫", "Veteran User"),
    ("翩跹", "Veteran User"),
    ("明星", "Veteran User"),
    ("副参领", "Veteran User"),
    ("上校", "Veteran User"),
    ("驱逐舰", "Veteran User"),
    ("宅护法", "Veteran User"),
    ("宅護法", "Veteran User"),
    ("insane", "Insane User"),
    ("insane user", "Insane User"),
    ("暹罗猫", "Insane User"),
    ("恋风", "Insane User"),
    ("领衔主演", "Insane User"),
    ("正军校", "Insane User"),
    ("中校", "Insane User"),
    ("邮轮", "Insane User"),
    ("宅传教士", "Insane User"),
    ("宅傳教士", "Insane User"),
    ("crazy", "Crazy User"),
    ("crazy user", "Crazy User"),
    ("雪鞋猫", "Crazy User"),
    ("主演", "Crazy User"),
    ("破茧", "Crazy User"),
    ("副军校", "Crazy User"),
    ("少校", "Crazy User"),
    ("赛艇", "Crazy User"),
    ("宅教士", "Crazy User"),
    ("精英", "Elite User"),
    ("elite user", "Elite User"),
    ("布偶猫", "Elite User"),
    ("配角", "Elite User"),
    ("军士", "Elite User"),
    ("化蛹", "Elite User"),
    ("尉官", "Elite User"),
    ("竹筏", "Elite User"),
    ("宅修士", "Elite User"),
    ("年轻气盛", "Power User"),
    ("易形", "Power User"),
    ("power", "Power User"),
    ("power user", "Power User"),
    ("加菲猫", "Power User"),
    ("跑龙套", "Power User"),
    ("士官", "Power User"),
    ("独木舟", "Power User"),
    ("御宅族", "Power User"),
    ("新人", "User"),
    ("临时演员", "User"),
    ("伯曼猫", "User"),
    ("萌动", "User"),
    ("平民", "User"),
    ("列兵", "User"),
    ("澡盆", "User"),
    ("路人", "User"),
    ("吸血鬼", "Peasant"),
    ("波斯猫", "Peasant"),
    ("游魂", "Peasant"),
    ("惊蛰", "Peasant"),
    ("叛徒", "Peasant"),
    ("庶民", "Peasant"),
    ("救生圈", "Peasant"),
    ("贫民", "Peasant"),
    ("异教徒", "Peasant"),
    ("uploader", "发布员 (Uploader)"),
    ("downloader", "发布员 (Uploader)"),
    ("保种员", "发布员 (Uploader)"),
    ("福音组", "发布员 (Uploader)"),
    ("福音組", "发布员 (Uploader)"),
    ("moderator", "总版主 (Moderator)"),
    ("管理员", "管理员 (Administrator)"),
    ("站长", "管理员 (Administrator)"),
    ("administrator", "管理员 (Administrator)"),
    ("中华田园猫", "管理员 (Administrator)"),
    ("sysop", "维护开发员 (Sysop)"),
    ("苏格兰折耳猫", "维护开发员 (Sysop)"),
    ("staff leader", "主管 (Staff Leader)"),
    ("阿比西尼亚猫", "主管 (Staff Leader)"),
    ("retiree", "养老族 (Retiree)"),
    ("养老族", "养老族 (Retiree)"),
    ("美国短毛猫", "养老族 (Retiree)"),
    ("vip", "贵宾 (VIP)"),
    ("贵宾", "贵宾 (VIP)"),
    ("貴賓", "贵宾 (VIP)"),
    ("挪威森林猫", "贵宾 (VIP)"),
    ("荣誉会员", "贵宾 (VIP)"),
    ("荣誉", "贵宾 (VIP)"),
    ("honor", "贵宾 (VIP)"),
    ("现充", "贵宾 (VIP)"),
    ("現充", "贵宾 (VIP)"),
    ("发布员", "发布员 (Uploader)"),
    ("英国短毛猫", "发布员 (Uploader)"),
    ("编辑员", "总版主 (Moderator)"),
    ("助理员", "总版主 (Moderator)"),
    ("总版主", "总版主 (Moderator)"),
    ("俄罗斯蓝猫", "总版主 (Moderator)"),
    ("管理员", "管理员 (Administrator)"),
    ("维护开发员", "维护开发员 (Sysop)"),
    ("主管", "主管 (Staff Leader)"),
    ("fff团", "总版主 (Moderator)"),
    ("fff團", "总版主 (Moderator)"),
    ("执事", "管理员 (Administrator)"),
    ("執事", "管理员 (Administrator)"),
    ("司铎", "管理员 (Administrator)"),
    ("司鐸", "管理员 (Administrator)"),
    ("枢机", "维护开发员 (Sysop)"),
    ("樞機", "维护开发员 (Sysop)"),
    ("站宗", "主管 (Staff Leader)"),
    ("peasant", "Peasant"),
    ("user", "User"),
]

# 通过等级图标文件名推断的映射
SRC_LEVEL_MAP = {
    "nexus": "Nexus Master",
    "ultimate": "Ultimate User",
    "extreme": "Extreme User",
    "veteran": "Veteran User",
    "insane": "Insane User",
    "crazy": "Crazy User",
    "elite": "Elite User",
    "power": "Power User",
    "user": "User",
    "peasant": "Peasant",
    "vip": "贵宾 (VIP)",
}

HIGH_PRIVACY_KEYWORDS = [
    "访问被用户",
    "保护其隐私",
    "拒绝访问",
    "private profile",
    "you do not have permission",
]

LEVEL_LABEL_EXCLUDE_KEYWORDS = ("截止", "日期", "期限", "限时", "限時", "到期")


def _sanitize_cookie_string(cookie: Optional[str]) -> str:
    """移除 Cookie 中的换行等无效字符，避免构造请求头时报错。"""
    if not cookie:
        return ""
    return re.sub(r"[\r\n]+", "; ", str(cookie)).strip()


def _is_normal_homepage_html(html: str, content_type: str = "") -> bool:
    """
    粗略判断返回内容是否为正常的首页 HTML 页面。
    要求具备 HTML/Body 结构，排除常见拦截页。
    """
    if not html:
        return False
    ct = (content_type or "").lower()
    if ct and "html" not in ct:
        return False
    lower_html = html.lower()
    if "<html" not in lower_html or "<body" not in lower_html:
        return False
    if any(block in lower_html for block in ("just a moment", "attention required", "access denied", "captcha")):
        return False
    soup = BeautifulSoup(html, "html.parser")
    if not soup or not soup.find("html") or not soup.find("body"):
        return False
    text_len = len((soup.get_text() or "").strip())
    return text_len > 30


def _looks_like_login_page(html: str) -> bool:
    """检测页面是否包含典型登录表单，减少因关键词误判登录状态的可能。"""
    if not html:
        return False
    soup = BeautifulSoup(html, "html.parser")
    if not soup:
        return False

    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        has_password = any((inp.get("type") or "").lower() == "password" for inp in inputs)
        if not has_password:
            continue
        action = (form.get("action") or "").lower()
        names = " ".join([(inp.get("name") or "") for inp in inputs]).lower()
        classes = " ".join(form.get("class") or []).lower()
        if any(kw in action for kw in ("login", "signin", "sign-in", "takelogin")):
            return True
        if any(kw in names for kw in ("login", "username", "password")):
            return True
        if any(kw in classes for kw in ("login", "signin")):
            return True

    text_lower = soup.get_text(" ", strip=True).lower()
    return "login" in text_lower and "password" in text_lower


def _has_auth_markers(text_lower: str, username_lower: str = "") -> bool:
    """检测页面上是否存在登录态标识（用户名/退出链接等）。"""
    logout_keywords = ("logout", "log out", "sign out", "退出", "退出登录", "登出", "注销")
    if username_lower and username_lower in text_lower:
        return True
    return any(kw in text_lower for kw in logout_keywords)


def _decode_html_response(res) -> str:
    """优先使用智能编码探测解码 HTML，避免编码异常导致的关键词漏检。"""
    if not res:
        return ""
    try:
        return RequestUtils.get_decoded_html_content(res, performance_mode=True)
    except Exception:
        try:
            return res.text or ""
        except Exception:
            return ""


def _detect_auth_state(html: str, username_lower: str = "", final_url: str = "") -> str:
    """
    基于 HTML 内容与最终 URL 估算当前登录态。
    返回值：logged_in / login / unknown
    """
    if not html:
        return "unknown"

    final_url_l = (final_url or "").lower()
    if any(key in final_url_l for key in ("login", "signin", "sign-in", "takelogin")):
        return "login"

    soup = BeautifulSoup(html, "html.parser")
    text_lower = ""
    try:
        text_lower = soup.get_text(" ", strip=True).lower() if soup else ""
    except Exception:
        text_lower = ""
    html_lower = html.lower()
    combined = " ".join(filter(None, [html_lower, text_lower]))

    if _has_auth_markers(combined, username_lower):
        return "logged_in"

    logged_in_markers = (
        "欢迎回来",
        "欢迎回家",
        "当前时间",
        "魔力值",
        "银元",
        "邀请",
        "收藏",
        "控制面板",
        "做种",
        "上传量",
        "下载量",
        "messages.php",
        "usercp.php",
        "logout.php",
        "mybonus.php",
        "torrents.php",
    )
    if any(marker.lower() in combined for marker in logged_in_markers):
        return "logged_in"

    if _looks_like_login_page(html):
        return "login"

    login_markers = ("please login", "please log in", "登陆", "登录", "登錄", "signin", "sign in", "密码", "密碼")
    if any(marker in combined for marker in login_markers):
        return "login"

    return "unknown"


# ----------------------------
# 配置管理
# ----------------------------
class ConfigManager:
    """封装插件配置与远端配置缓存。"""

    DEFAULT_CONFIG: Dict[str, Any] = {
        "enabled": False,
        "api_token": "",
        "review_cron": "*/5 * * * *",
        "daily_report_cron": "0 23 * * *",
        "config_sync_interval_minutes": 10,
        "log_refresh_interval_minutes": 10,
        "run_cookie_check_once": False,
        "run_parse_check_once": False,
        "cookie_check_interval_minutes": 60,
        "notify_review_result": True,
        "notify_exception": True,
        "notify_pending": True,
        "status_retry_count": 3,
        "status_retry_interval_seconds": 30,
        "api_base_url": "https://pt.luckpt.de",
        "api_proxy": "",
        "test_parse_url": "",
    }

    def __init__(self, plugin: "_PluginBase", config: Optional[dict]):
        self.plugin = plugin
        merged = dict(self.DEFAULT_CONFIG)
        merged.update(config or {})
        self.config = merged

        self.remote_config_cache: Dict[str, Any] = plugin.get_data("remote_config_cache") or {}
        self.remote_config_ts: Optional[str] = plugin.get_data("remote_config_synced_at")
        self.last_log_fetch: Optional[str] = plugin.get_data("last_log_fetch")

    # --- 基础字段 ---
    @property
    def enabled(self) -> bool:
        return bool(self.config.get("enabled"))

    @property
    def api_token(self) -> str:
        return self.config.get("api_token") or ""

    @property
    def api_base(self) -> str:
        default_base = getattr(settings, "LUCKPT_REVIEW_API", self.DEFAULT_CONFIG["api_base_url"])
        base = self.config.get("api_base_url") or default_base
        return base.rstrip("/")

    @property
    def api_proxy(self) -> Optional[str]:
        proxy = str(self.config.get("api_proxy") or "").strip()
        return proxy or None

    @property
    def api_proxies(self) -> Optional[Dict[str, str]]:
        proxy = self.api_proxy
        if not proxy:
            return None
        return {"http": proxy, "https": proxy}

    @property
    def review_cron(self) -> str:
        return self.config.get("review_cron") or "*/5 * * * *"

    @property
    def daily_report_cron(self) -> Optional[str]:
        value = self.config.get("daily_report_cron")
        if value is None:
            return "0 23 * * *"
        value = str(value).strip()
        return value or None

    @property
    def config_sync_interval(self) -> int:
        return int(self.config.get("config_sync_interval_minutes") or 10)

    @property
    def cookie_check_interval(self) -> int:
        return int(self.config.get("cookie_check_interval_minutes") or 60)

    @property
    def log_refresh_interval(self) -> int:
        return int(self.config.get("log_refresh_interval_minutes") or 10)

    @property
    def status_retry_count(self) -> int:
        return int(self.config.get("status_retry_count") or 3)

    @property
    def status_retry_interval(self) -> int:
        return int(self.config.get("status_retry_interval_seconds") or 30)

    @property
    def auto_review_enabled_remote(self) -> bool:
        # 当远端关闭自动审核时，本地仅保留检测任务
        return str(self.remote_config_cache.get("auto_review_enabled", "true")).lower() == "true"

    @property
    def min_user_class(self) -> str:
        return self.remote_config_cache.get("min_user_class") or "User"

    @property
    def verification_level(self) -> str:
        level = str((self.remote_config_cache or {}).get("verification_level") or "high").lower()
        return "low" if level == "low" else "high"

    def parse_rule(self, site_key: str) -> Dict[str, Any]:
        rules = (self.remote_config_cache or {}).get("parse_overrides") or {}
        return rules.get(site_key) or {}

    def level_aliases(self, site_key: str) -> Dict[str, str]:
        aliases = (self.remote_config_cache or {}).get("level_aliases") or {}
        site_rules = self.parse_rule(site_key) or {}
        site_level_alias = site_rules.get("level_aliases") or {}
        merged = dict(aliases)
        merged.update(site_level_alias)
        return merged

    @property
    def remote_sites(self) -> List[Dict[str, Any]]:
        return self.remote_config_cache.get("sites") or []

    def update_config(self, new_config: Dict[str, Any]):
        self.config.update(new_config)
        self.plugin.update_config(self.config)

    def clear_oneoff_flag(self, key: str):
        if key not in ("run_cookie_check_once", "run_parse_check_once"):
            return
        if self.config.get(key):
            self.config[key] = False
            self.plugin.update_config(self.config)

    def should_run_test_parse(self) -> Optional[str]:
        url = (self.config or {}).get("test_parse_url")
        if url and isinstance(url, str) and url.strip():
            return url.strip()
        return None

    def update_remote_cache(self, data: Dict[str, Any]):
        old_site_keys = {s.get("key") or s.get("site_key") for s in self.remote_sites if s}
        self.remote_config_cache = data or {}
        new_site_keys = {s.get("key") or s.get("site_key") for s in self.remote_sites if s}
        ts = datetime.now().isoformat()
        self.remote_config_ts = ts
        self.plugin.save_data("remote_config_cache", self.remote_config_cache)
        self.plugin.save_data("remote_config_synced_at", ts)

        removed_keys = {k for k in old_site_keys if k and k not in new_site_keys}
        if removed_keys:
            cookie_status = self.plugin.get_data("cookie_status") or {}
            removed = False
            for key in list(cookie_status.keys()):
                if key in removed_keys:
                    cookie_status.pop(key, None)
                    removed = True
            if removed:
                self.plugin.save_data("cookie_status", cookie_status)

            parse_results = self.plugin.get_data("parse_check_results") or []
            filtered = [r for r in parse_results if (r.get("site_key") not in removed_keys)]
            if len(filtered) != len(parse_results):
                self.plugin.save_data("parse_check_results", filtered)

        logger.info(
            "审核系统配置已同步：min_user_class=%s, sites=%s, auto_review_enabled=%s",
            self.min_user_class,
            len(self.remote_sites),
            self.auto_review_enabled_remote,
        )

    def should_sync_remote(self) -> bool:
        if not self.remote_config_ts:
            return True
        try:
            last = datetime.fromisoformat(self.remote_config_ts)
            return datetime.now(last.tzinfo) - last >= timedelta(minutes=self.config_sync_interval)
        except Exception:
            return True

    def record_log_fetch(self):
        ts = datetime.now().isoformat()
        self.last_log_fetch = ts
        self.plugin.save_data("last_log_fetch", ts)

    def should_fetch_logs(self) -> bool:
        if not self.last_log_fetch:
            return True
        try:
            last = datetime.fromisoformat(self.last_log_fetch)
            return datetime.now(last.tzinfo) - last >= timedelta(minutes=self.log_refresh_interval)
        except Exception:
            return True


# ----------------------------
# 站点与 Cookie 管理
# ----------------------------
class SiteRegistry:
    """聚合远端站点与本地站点，并负责 Cookie 状态缓存。"""

    def __init__(self, plugin: "_PluginBase", config: ConfigManager, sites_helper: SitesHelper):
        self.plugin = plugin
        self.config_mgr = config
        self.sites_helper = sites_helper
        self.cookie_status: Dict[str, Dict[str, Any]] = plugin.get_data("cookie_status") or {}
        self.site_mapping: Dict[str, Dict[str, Any]] = {}
        self._last_refresh_config_ts: Optional[str] = None

    def refresh(self):
        local_sites = self.sites_helper.get_indexers() or []
        remote_sites = self.config_mgr.remote_sites

        mapping: Dict[str, Dict[str, Any]] = {}
        local_by_key = {}
        for site in local_sites:
            key = (site.get("pri_name") or site.get("name") or "").lower()
            domain = urlparse(site.get("url") or "").netloc
            local_by_key[key] = site
            if domain:
                local_by_key[domain] = site
        for remote in remote_sites:
            key = remote.get("key") or remote.get("site_key") or ""
            domain = urlparse(remote.get("url") or "").netloc
            local_match = local_by_key.get(key.lower()) or local_by_key.get(domain.lower())
            mapping[key] = {
                "remote": remote,
                "local": local_match,
                "domain": domain,
                "has_cookie": bool(local_match and local_match.get("cookie")),
            }
        self.site_mapping = mapping
        self._last_refresh_config_ts = self.config_mgr.remote_config_ts
        self._prune_stale_data()

    def _prune_stale_data(self):
        """
        移除已不存在的站点缓存，避免远端删除站点后仍然出现在本地。
        """
        active_keys = set(self.site_mapping.keys())
        stale_cookie_keys = [k for k in list(self.cookie_status.keys()) if k not in active_keys]
        if stale_cookie_keys:
            for key in stale_cookie_keys:
                self.cookie_status.pop(key, None)
            self.plugin.save_data("cookie_status", self.cookie_status)
            logger.info("已清理过期的 Cookie 状态缓存：%s", ",".join(stale_cookie_keys))

        parse_results = self.plugin.get_data("parse_check_results") or []
        filtered = [r for r in parse_results if r.get("site_key") in active_keys]
        if len(filtered) != len(parse_results):
            self.plugin.save_data("parse_check_results", filtered)
            logger.info("已清理过期的解析检测结果，移除 %s 条", len(parse_results) - len(filtered))

    def match_site_account(self, site_account: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        site_key = site_account.get("site_key") or site_account.get("key")
        url_host = urlparse(site_account.get("url") or "").netloc
        if not self.site_mapping or self._last_refresh_config_ts != self.config_mgr.remote_config_ts:
            self.refresh()
        match = self.site_mapping.get(site_key) or self.site_mapping.get(url_host)
        if match:
            return match
        # 容错：尝试主域名匹配
        for key, value in self.site_mapping.items():
            if value.get("domain") == url_host:
                return value
        return None

    def update_cookie_status(self, site_key: str, status: Dict[str, Any]):
        self.cookie_status[site_key] = status
        self.plugin.save_data("cookie_status", self.cookie_status)

    def check_cookie_validity(self, site_key: str, site: Dict[str, Any]) -> Dict[str, Any]:
        result = {
            "site_key": site_key,
            "site_name": (site.get("remote") or {}).get("name") or site_key,
            "valid": False,
            "matched": bool(site.get("local")),
            "reason": "",
            "checked_at": datetime.now().isoformat(),
        }
        if not site.get("local"):
            result["reason"] = "本地未配置站点"
            return result
        cookie = _sanitize_cookie_string(site["local"].get("cookie"))
        ua = site["local"].get("ua") or settings.USER_AGENT
        base_url = (site.get("remote") or {}).get("url") or site["local"].get("url")
        if not cookie or not base_url:
            result["reason"] = "缺少站点 URL 或 Cookie"
            return result

        try:
            req = RequestUtils(headers={"Cookie": cookie, "User-Agent": ua}, timeout=30)
            res = req.get_res(base_url, allow_redirects=True)
            if not res:
                result["reason"] = "无响应"
                return result
            final_url = getattr(res, "url", "") or base_url
            if res.status_code in (301, 302) and "login" in (res.headers.get("Location") or "").lower():
                result["reason"] = "跳转登录页"
                return result
            if res.status_code != 200:
                result["reason"] = f"HTTP {res.status_code}"
                return result
            html_text = _decode_html_response(res)
            if not html_text:
                result["reason"] = "返回空页面"
                return result
            username_lower = (site["local"].get("username") or "").lower()
            auth_state = _detect_auth_state(html_text, username_lower, final_url)
            if auth_state == "login":
                result["reason"] = "页面疑似登录页（检测到登录跳转或登录表单）"
                return result
            is_normal_html = _is_normal_homepage_html(html_text, res.headers.get("Content-Type"))
            if not is_normal_html and auth_state != "logged_in":
                result["reason"] = "返回非首页 HTML 页面"
                return result
            result["valid"] = True
            result["reason"] = ""
        except Exception as exc:
            result["reason"] = f"检测异常: {exc}"
            logger.error("检测站点 %s Cookie 失败: %s", site_key, exc)
        return result

    def _check_cookie_with_retry(self, site_key: str, site: Dict[str, Any], attempts: int = 5, delay: float = 1.0):
        status = None
        for idx in range(attempts):
            status = self.check_cookie_validity(site_key, site)
            reason = status.get("reason") or ""
            if status.get("valid"):
                break
            if not reason or not any(keyword in reason for keyword in ("无响应", "异常", "超时", "访问失败")):
                break
            if idx < attempts - 1:
                time.sleep(delay)
        return status

    def run_cookie_check(self) -> List[Dict[str, Any]]:
        self.refresh()
        reports: List[Dict[str, Any]] = []
        logger.info("开始 Cookie 有效性检测，站点数=%s", len(self.site_mapping))
        futures = {}
        with ThreadPoolExecutor(max_workers=8) as executor:
            for key, site in self.site_mapping.items():
                futures[executor.submit(self._check_cookie_with_retry, key, site)] = key
            for future in as_completed(futures):
                key = futures[future]
                try:
                    status = future.result()
                except Exception as exc:
                    logger.error("Cookie检测并发任务异常：站点=%s 错误=%s", key, exc)
                    status = {
                        "site_key": key,
                        "site_name": key,
                        "valid": False,
                        "matched": False,
                        "reason": f"并发检测异常: {exc}",
                        "checked_at": datetime.now().isoformat(),
                    }
                prev = self.cookie_status.get(key)
                self.update_cookie_status(key, status)
                reports.append(status)
                logger.debug(
                    "Cookie检测 站点=%s 匹配=%s 有效=%s 原因=%s",
                    key,
                    status.get("matched"),
                    status.get("valid"),
                    status.get("reason"),
                )
        valid_cnt = len([r for r in reports if r.get("valid")])
        invalid_cnt = len([r for r in reports if r.get("matched") and not r.get("valid")])
        unmatched_cnt = len([r for r in reports if not r.get("matched")])
        logger.info(
            "Cookie检测结束：有效=%s 失效=%s 未匹配=%s 总计=%s",
            valid_cnt,
            invalid_cnt,
            unmatched_cnt,
            len(reports),
        )
        return reports

    def retry_failed_cookies(self) -> List[Dict[str, Any]]:
        """
        对已检测为失效的 Cookie 进行快速重试，周期性触发，避免卡在偶发网络波动。
        仅针对已匹配站点且 valid=False 的记录。
        """
        self.refresh()
        targets = [k for k, v in (self.cookie_status or {}).items() if v and v.get("matched") and not v.get("valid")]
        if not targets:
            return []
        reports: List[Dict[str, Any]] = []
        logger.info("开始失败 Cookie 重试，站点数=%s", len(targets))
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_map = {executor.submit(self._check_cookie_with_retry, key, self.site_mapping.get(key) or {}): key for key in targets}
            for future in as_completed(future_map):
                key = future_map[future]
                try:
                    status = future.result()
                except Exception as exc:
                    logger.error("Cookie重试并发任务异常：站点=%s 错误=%s", key, exc)
                    status = {
                        "site_key": key,
                        "site_name": key,
                        "valid": False,
                        "matched": False,
                        "reason": f"并发重试异常: {exc}",
                        "checked_at": datetime.now().isoformat(),
                    }
                self.update_cookie_status(key, status)
                reports.append(status)
        recovered = len([r for r in reports if r.get("valid")])
        still_bad = len([r for r in reports if not r.get("valid") and r.get("matched")])
        logger.info("失败 Cookie 重试结束：恢复=%s 仍失效=%s 总计=%s", recovered, still_bad, len(reports))
        return reports


# ----------------------------
# 解析引擎
# ----------------------------
class ParserEngine:
    """解析站点页面并执行等级与隐私判定。"""

    def __init__(self, config_mgr: ConfigManager):
        self.config_mgr = config_mgr

    @staticmethod
    def _normalize_level_text(value: str) -> Tuple[str, str]:
        text = value.lower()
        compact = re.sub(r"[^a-z0-9\u4e00-\u9fa5]+", "", text)
        return text, compact

    def _match_level_by_keywords(self, raw: str) -> Optional[str]:
        text, compact = self._normalize_level_text(raw)
        for kw, target in LEVEL_KEYWORDS:
            kw_compact = kw.replace(" ", "")
            if kw in text or kw_compact in compact:
                return target
        return None

    @staticmethod
    def _clean_text(value: Optional[str]) -> str:
        if not value:
            return ""
        return " ".join(value.replace("\xa0", " ").split())

    def _find_value_by_labels(self, soup: BeautifulSoup, labels: List[str]) -> Optional[str]:
        """在表格类结构中通过标签查找相邻值。"""
        if not soup:
            return None
        keys = [lbl.lower() for lbl in labels if lbl]

        def _match(text: Any) -> bool:
            if not isinstance(text, str):
                return False
            lower_text = text.strip().lower()
            if any(ex in lower_text for ex in LEVEL_LABEL_EXCLUDE_KEYWORDS):
                return False
            return any(k in lower_text for k in keys)

        cells = soup.find_all(["td", "th"], string=_match)
        for cell in cells:
            text_in_cell = self._clean_text(cell.get_text(" ", strip=True))
            if text_in_cell and "@" in text_in_cell:
                # 支持“邮箱 xxx@example.com”同单元格写法
                for kw in keys:
                    if kw in text_in_cell.lower():
                        cleaned = text_in_cell.replace(kw, "", 1).strip(" :：-")
                        if cleaned:
                            return cleaned
            sibling = cell.find_next_sibling(["td", "th"])
            if sibling:
                img = sibling.find("img", title=True) or sibling.find("img", alt=True)
                if img and (img.get("title") or img.get("alt")):
                    candidate = self._clean_text(img.get("title") or img.get("alt"))
                    if candidate:
                        return candidate
                candidate = self._clean_text(sibling.get_text(" ", strip=True))
                if candidate:
                    return candidate
            parent = cell.parent
            if parent:
                siblings = [c for c in parent.find_all(["td", "th"]) if c is not cell]
                for sib in siblings:
                    img = sib.find("img", title=True) or sib.find("img", alt=True)
                    if img and (img.get("title") or img.get("alt")):
                        candidate = self._clean_text(img.get("title") or img.get("alt"))
                        if candidate:
                            return candidate
                    candidate = self._clean_text(sib.get_text(" ", strip=True))
                    if candidate:
                        return candidate
        return None

    def _extract_label_map(self, soup: BeautifulSoup) -> Dict[str, str]:
        """
        兜底提取类似“标签 + 值”两列表格的映射，便于当常规解析缺失时快速补齐。
        仅用作缺失字段的后备来源，不覆盖已解析出的值。
        """
        mapping: Dict[str, str] = {}
        if not soup:
            return mapping
        for row in soup.find_all("tr"):
            cells = row.find_all(["td", "th"])
            if len(cells) < 2:
                continue
            label_raw = self._clean_text(cells[0].get_text(" ", strip=True))
            if not label_raw:
                continue
            value_cell = cells[1]
            value = None
            img = value_cell.find("img", title=True) or value_cell.find("img", alt=True)
            if img and (img.get("title") or img.get("alt")):
                value = self._clean_text(img.get("title") or img.get("alt"))
            if not value:
                val_text = self._clean_text(value_cell.get_text(" ", strip=True))
                if val_text:
                    value = val_text
            if value:
                mapping[label_raw.lower()] = value
        return mapping

    def normalize_level(self, raw: str, overrides: Optional[Dict[str, str]] = None) -> Tuple[Optional[str], Optional[int]]:
        if not raw:
            return None, None
        normalized_candidate = raw.strip()
        override_map = {k.lower(): v for k, v in (overrides or {}).items()}
        candidate_l = normalized_candidate.lower()
        if candidate_l in override_map:
            normalized_candidate = override_map[candidate_l]
        elif candidate_l in DEFAULT_LEVEL_ALIASES:
            normalized_candidate = DEFAULT_LEVEL_ALIASES[candidate_l]
        else:
            fuzzy_match = self._match_level_by_keywords(normalized_candidate)
            if fuzzy_match:
                normalized_candidate = fuzzy_match
        try:
            index = LEVEL_ORDER.index(normalized_candidate) + 1
            return normalized_candidate, index
        except ValueError:
            return normalized_candidate, None

    def detect_privacy(self, html_text: str, email: Optional[str], username: Optional[str]) -> str:
        text_lower = (html_text or "").lower()
        for kw in HIGH_PRIVACY_KEYWORDS:
            if kw.lower() in text_lower:
                return "high"
        # 页面仅露出用户名，邮箱缺失，通常为隐私中等
        if username and not email:
            # 页面同时出现“拒绝访问/保护隐私”时提升为高隐私
            if any(k in text_lower for k in ("拒绝访问", "被用户", "隐私")):
                return "high"
            return "mid"
        if username and email:
            return "low"
        # 既无邮箱也无用户名时默认中隐私
        return "mid"

    def parse_page(
        self, html: str, site_key: str = "", overrides: Optional[Dict[str, Any]] = None, strip_nav: bool = True
    ) -> Dict[str, Any]:
        rules = overrides or {}
        # 优先使用远端配置里的解析规则与等级映射
        parse_overrides = (self.config_mgr.remote_config_cache or {}).get("parse_overrides") or {}
        if site_key and site_key in parse_overrides and not overrides:
            rules = parse_overrides.get(site_key) or {}
        level_alias_source = rules.get("level_aliases") or (self.config_mgr.remote_config_cache or {}).get("level_aliases") or {}
        base_url = rules.get("base_url") or ""
        uid_from_url = None
        try:
            uid_from_url = parse_qs(urlparse(base_url).query).get("id", [None])[0]
        except Exception:
            uid_from_url = None

        soup = BeautifulSoup(html, "html.parser")
        # 去除全局导航/头部区域，避免拿到当前登录用户昵称
        if strip_nav:
            try:
                for node in soup.select("#nav_block, #info_block"):
                    node.decompose()
            except Exception:
                pass

        def _is_valid_username(text: str) -> bool:
            if not text:
                return False
            text_clean = self._clean_text(text)
            if not text_clean or len(text_clean) > 32:
                return False
            banned = ["上传量", "下载量", "考核", "需要", "邀请", "魔力值", "天", "小时", "hour", "day"]
            return not any(b in text_clean for b in banned)

        def _sanitize_username_candidate(text: str) -> str:
            """尽量提取疑似用户名的最短片段。"""
            if not text:
                return ""
            cleaned = self._clean_text(text)
            # 切掉分隔符后的站点名/标语
            for sep in ("|", "｜", "-", "—"):
                if sep in cleaned:
                    cleaned = cleaned.split(sep)[0].strip()
            # 取第一个空白前的片段
            if " " in cleaned:
                cleaned = cleaned.split(" ")[0].strip()
            return cleaned

        username = None
        email = None
        level_raw = None
        profile_url = None
        register_time = None
        label_map: Dict[str, str] = {}
        site_key_l = (site_key or "").lower()
        base_url_l = (base_url or "").lower()
        is_open_cd = site_key_l in ("opencd", "open.cd", "open_cd") or "open.cd" in base_url_l

        def _pick_level_from_imgs(imgs) -> Optional[str]:
            """根据图片的 title/alt/src/class 提取等级。"""
            for img in imgs or []:
                title_or_alt = self._clean_text((img.get("title") or img.get("alt") or ""))
                if title_or_alt:
                    title_l = title_or_alt.lower()
                    if title_l in DEFAULT_LEVEL_ALIASES:
                        return DEFAULT_LEVEL_ALIASES[title_l]
                    matched = self._match_level_by_keywords(title_or_alt)
                    if matched:
                        return matched
                    if title_or_alt in LEVEL_ORDER:
                        return title_or_alt
                src = img.get("src") or ""
                fname = urlparse(src).path.lower()
                for key, val in SRC_LEVEL_MAP.items():
                    if key in fname:
                        return val
                cls = " ".join(img.get("class") or [])
                if cls:
                    cls_match = self._match_level_by_keywords(cls)
                    if cls_match:
                        return cls_match
            return None

        # 用户名解析：优先自定义选择器/正则
        if rules.get("username_selector"):
            tag = soup.select_one(rules["username_selector"])
            if tag and tag.get_text(strip=True):
                username = tag.get_text(strip=True)
        if not username and rules.get("username_regex"):
            m = re.search(rules["username_regex"], html or "", re.IGNORECASE | re.MULTILINE)
            if m:
                username = m.group(1).strip()
        if not username:
            title_tag = soup.find("title")
            if title_tag and title_tag.text:
                m_title = re.search(r"用户详情\s*-\s*([^-|]+)", title_tag.text)
                if m_title:
                    title_name = _sanitize_username_candidate(m_title.group(1))
                    if _is_valid_username(title_name):
                        username = title_name
        if not username:
            h1_tag = soup.find("h1") or soup.select_one("#outer h1")
            if h1_tag:
                # 优先 h1 内的个人链接
                link_h1 = None
                if uid_from_url:
                    link_h1 = h1_tag.find("a", href=lambda href: href and "userdetails" in href.lower() and f"id={uid_from_url}" in href)
                if not link_h1:
                    link_h1 = h1_tag.find("a", href=lambda href: href and "userdetails" in href.lower())
                if link_h1 and link_h1.get_text(strip=True):
                    candidate = _sanitize_username_candidate(link_h1.get_text(strip=True))
                    if _is_valid_username(candidate):
                        username = candidate
                if not username:
                    h1_texts = [s.strip() for s in h1_tag.stripped_strings if s and s.strip()]
                    if h1_texts:
                        candidate = _sanitize_username_candidate(h1_texts[0])
                        if _is_valid_username(candidate):
                            username = candidate
            if not username:
                username_tag = soup.select_one("#outer h1 b") or soup.select_one("h1 b")
                if username_tag and username_tag.text:
                    candidate = _sanitize_username_candidate(username_tag.text)
                    if _is_valid_username(candidate):
                        username = candidate
        if not username:
            # 根据 userdetails 链接提取（优先匹配当前 UID）
            link_tag = None
            if uid_from_url:
                link_tag = soup.find(
                    "a",
                    href=lambda href: href and "userdetails" in href.lower() and f"id={uid_from_url}" in href,
                )
            if not link_tag:
                # 退化到任意 userdetails 链接，但仅接受疑似用户名的短文本
                for candidate_link in soup.find_all("a", href=lambda href: href and "userdetails" in href.lower()):
                    candidate_text = _sanitize_username_candidate(candidate_link.get_text(strip=True))
                    if _is_valid_username(candidate_text):
                        link_tag = candidate_link
                        break
            if link_tag and link_tag.get_text(strip=True):
                candidate = _sanitize_username_candidate(link_tag.get_text(strip=True))
                if _is_valid_username(candidate):
                    username = candidate
        if not username:
            nowrap_spans = soup.find_all("span", class_=lambda c: c and "nowrap" in c.split())
            for span in nowrap_spans:
                link = None
                if uid_from_url:
                    link = span.find(
                        "a",
                        href=lambda href: href and "userdetails" in href.lower() and f"id={uid_from_url}" in href,
                    )
                if not link:
                    link = span.find("a", href=lambda href: href and "userdetails" in href.lower())
                if link and link.get_text(strip=True):
                    candidate = _sanitize_username_candidate(link.get_text(strip=True))
                    if _is_valid_username(candidate):
                        username = candidate
                        break
                text_iter = (s.strip() for s in span.stripped_strings if s and s.strip())
                username_candidate = next(text_iter, None)
                candidate = _sanitize_username_candidate(username_candidate) if username_candidate else None
                if candidate and _is_valid_username(candidate):
                    username = candidate
                    break
        if not username:
            label_username = self._find_value_by_labels(soup, ["用户名", "用戶名", "nickname", "user name"])
            if label_username:
                username = self._clean_text(label_username)

        # 邮箱解析
        mail_link = None
        if rules.get("email_selector"):
            mail_link = soup.select_one(rules["email_selector"])
        if not mail_link:
            mail_link = soup.find("a", href=lambda href: href and href.startswith("mailto:"))
        if mail_link:
            email = mail_link.text.strip() or (mail_link.get("href", "").split(":")[1] if mail_link.get("href") else None)
        else:
            email_td = soup.find("td", string=lambda s: isinstance(s, str) and ("邮箱" in s or "email" in s.lower()))
            if email_td and email_td.find_next_sibling("td"):
                candidate = email_td.find_next_sibling("td")
                mail_tag = candidate.find("a", href=lambda href: href and href.startswith("mailto:"))
                if mail_tag:
                    email = mail_tag.text.strip()
                else:
                    candidate_text = candidate.get_text(strip=True)
                    if "@" in candidate_text:
                        email = candidate_text
        if not email:
            email_label_value = self._find_value_by_labels(soup, ["邮箱", "email", "e-mail", "mail"])
            if email_label_value and "@" in email_label_value:
                email = self._clean_text(email_label_value)
            if not email and rules.get("email_regex"):
                m = re.search(rules["email_regex"], html or "", re.IGNORECASE)
                if m:
                    email = m.group(1).strip()
            if not email:
                # 最终回退：先尝试“邮箱 xxx”模式，再扫描第一个邮箱
                text_all = soup.get_text(" ", strip=True) or ""
                m_label_email = re.search(r"(邮箱|email)[：: ]+([\w.+'%-]+@[\w.-]+)", text_all, re.IGNORECASE)
                match = None
                if m_label_email:
                    email = m_label_email.group(2).strip()
                if not email:
                    match = re.search(r"[\w.+'%-]+@[\w.-]+", text_all)
                    if match:
                        email = match.group(0).strip()
            if not email:
                if not label_map:
                    label_map = self._extract_label_map(soup)
                for key in ("邮箱", "email", "e-mail", "mail"):
                    val = label_map.get(key.lower())
                    if val and "@" in val:
                        email = val
                        break
        # OpenCD 页脚的联系邮箱，若无个人邮箱则应忽略
        if is_open_cd and email and email.lower() == "opencd.service@gmail.com":
            email = None

        # 等级解析
        level_td = None
        level_text_candidate = None
        level_cell_has_img = False
        if rules.get("level_selector"):
            level_td = soup.select_one(rules["level_selector"])
        if not level_td:
            def _is_level_cell(val: Any) -> bool:
                if not isinstance(val, str):
                    return False
                lower_val = val.lower()
                if not ("等级" in val or "class" in lower_val):
                    return False
                return not any(ex in lower_val for ex in LEVEL_LABEL_EXCLUDE_KEYWORDS)

            candidates = soup.find_all("td", string=_is_level_cell)
            if candidates:
                level_td = candidates[0].find_next_sibling("td") or candidates[0]
        if level_td:
            imgs = level_td.find_all("img")
            if imgs:
                level_cell_has_img = True
            level_from_imgs = _pick_level_from_imgs(imgs)
            if level_from_imgs:
                level_raw = level_from_imgs
            if not level_raw:
                text = level_td.get_text(" ", strip=True)
                if text:
                    text_cleaned = self._clean_text(text)
                    # 仅在文本含有等级关键词时直接作为等级，否则暂存为候选，避免误判为个人称号
                    if self._match_level_by_keywords(text_cleaned) or text_cleaned.lower() in DEFAULT_LEVEL_ALIASES:
                        level_raw = text_cleaned
                    elif not level_cell_has_img:
                        # 仅在单元格没有等级图标时，才把纯文本当作候选，避免把个性签名当成等级
                        level_text_candidate = text_cleaned
        if not level_raw and rules.get("level_regex"):
            m = re.search(rules["level_regex"], html or "", re.IGNORECASE)
            if m:
                level_raw = m.group(1).strip()
        if not level_raw:
            level_by_label = self._find_value_by_labels(soup, ["等级", "class", "用户组", "等級", "级别"])
            if level_by_label:
                level_raw = self._clean_text(level_by_label)
        if not level_raw:
            if not label_map:
                label_map = self._extract_label_map(soup)
            for key in ("等级", "class", "用户组", "等級", "级别"):
                val = label_map.get(key.lower())
                if val:
                    level_raw = val
                    break
        # 兜底：扫描页面内所有等级图标
        if not level_raw:
            level_from_imgs = _pick_level_from_imgs(soup.find_all("img"))
            if level_from_imgs:
                level_raw = level_from_imgs
        if not level_raw and level_text_candidate:
            level_raw = level_text_candidate
        if level_raw:
            level_raw = self._clean_text(level_raw)

        # 个人主页链接（用于二次解析）
        if rules.get("profile_selector"):
            link_tag = soup.select_one(rules["profile_selector"])
            if link_tag and link_tag.get("href"):
                profile_url = urljoin(base_url, link_tag["href"])
        if not profile_url:
            link_tag = soup.find("a", href=lambda href: href and "userdetails" in href.lower())
            if link_tag and link_tag.get("href"):
                profile_url = urljoin(base_url, link_tag["href"]) if base_url else link_tag["href"]

        # 注册时间解析
        if rules.get("register_time_selector"):
            reg_tag = soup.select_one(rules["register_time_selector"])
            if reg_tag:
                register_time = self._clean_text(reg_tag.get_text(" ", strip=True))
        if not register_time and rules.get("register_time_regex"):
            m = re.search(rules["register_time_regex"], html or "", re.IGNORECASE)
            if m:
                register_time = self._clean_text(m.group(1))
        if not register_time:
            register_time = self._find_value_by_labels(
                soup,
                ["注册时间", "加入日期", "入站时间", "join date", "registration date", "加入时间"],
            )
            if register_time:
                register_time = self._clean_text(register_time.split("(")[0])
        if not register_time:
            if not label_map:
                label_map = self._extract_label_map(soup)
            for key in ("注册时间", "加入日期", "入站时间", "join date", "registration date", "加入时间"):
                val = label_map.get(key.lower())
                if val:
                    register_time = self._clean_text(val.split("(")[0])
                    if register_time:
                        break
        if not register_time:
            m = re.search(
                r"(注册时间|加入日期|Join Date)[：: ]+([^<\\n]+)",
                soup.get_text(" ", strip=True),
                re.IGNORECASE,
            )
            if m:
                register_time = self._clean_text(m.group(2).split("(")[0])

        # 针对 OpenCD 主页的定向兜底：优先取表格行中的邮箱/等级/加入日期，避免页脚邮箱误判
        if is_open_cd:
            # 行值提取器：从包含标签的单元格拿到下一个 td 的文本/链接
            def _row_value(label_keywords: List[str]) -> Tuple[Optional[str], Optional[Any]]:
                cell = soup.find("td", string=lambda s: isinstance(s, str) and any(k in s for k in label_keywords))
                if not cell:
                    return None, None
                value_td = cell.find_next_sibling("td") or cell
                mail_tag = value_td.find("a", href=lambda href: href and href.startswith("mailto:"))
                if mail_tag and mail_tag.text:
                    return mail_tag.text.strip(), value_td
                text_val = value_td.get_text(" ", strip=True) or None
                return self._clean_text(text_val) if text_val else None, value_td

            email_val, email_td_node = _row_value(["邮箱", "email", "Email"])
            if email_val and (not email or email.lower() == "opencd.service@gmail.com"):
                email = email_val

            level_val, level_td_node = _row_value(["等级", "class", "用户组", "級別", "等級"])
            if level_td_node:
                img = level_td_node.find("img", title=True) or level_td_node.find("img", alt=True)
                if img and (img.get("title") or img.get("alt")):
                    level_val = self._clean_text(img.get("title") or img.get("alt"))
            if level_val and (not level_raw or level_raw.lower() == level_val.lower() or self.normalize_level(level_raw)[1] is None):
                level_raw = level_val

            reg_val, _ = _row_value(["加入日期", "注册时间", "入站时间", "Join Date"])
            if reg_val:
                reg_val = reg_val.split("(")[0].strip()
            if reg_val and not register_time:
                register_time = reg_val

        # 标准化等级（支持自定义映射）
        level_standard, level_index = self.normalize_level(level_raw, level_alias_source)
        # 若已识别到的等级无法标准化，再尝试从等级单元格/全局图片重取一次，避免把个人称号当等级
        if level_raw and level_index is None:
            img_level = _pick_level_from_imgs(level_td.find_all("img")) if level_td else None
            if not img_level:
                img_level = _pick_level_from_imgs(soup.find_all("img"))
            if img_level:
                level_raw = img_level
                level_standard, level_index = self.normalize_level(level_raw, level_alias_source)

        privacy = self.detect_privacy(html, email, username)
        return {
            "username": username,
            "email": email,
            "level_raw": level_raw,
            "level_standard": level_standard,
            "level_index": level_index,
            "privacy_level": privacy,
            "profile_url": profile_url,
            "register_time": register_time,
        }


# ----------------------------
# 审核流程引擎
# ----------------------------
class ReviewEngine:
    """执行自动审核完整流程。"""

    SKIP_CACHE_HOURS = 48

    def __init__(self, plugin: "_PluginBase", config: ConfigManager, registry: SiteRegistry, parser: ParserEngine):
        self.plugin = plugin
        self.config_mgr = config
        self.registry = registry
        self.parser = parser
        self.running = False
        self.stats = plugin.get_data("review_health_stats") or {
            "approve": 0,
            "reject": 0,
            "failed": 0,
            "skipped_no_cookie": 0,
        }
        self.skip_history = plugin.get_data("skip_history") or {}
        self.lock_tracker = plugin.get_data("lock_tracker") or {}
        self.lock_blacklist = plugin.get_data("lock_blacklist") or {}
        self._ensure_daily_stats_initialized()
        self._cleanup_skip_history()
        self._cleanup_lock_blacklist()
        self._cleanup_lock_tracker()

    def _ensure_daily_stats_initialized(self):
        stats = self._get_daily_stats()
        self.plugin.save_data("daily_review_stats", stats)

    def _get_daily_stats(self) -> Dict[str, Any]:
        today = datetime.now().strftime("%Y-%m-%d")
        stored = self.plugin.get_data("daily_review_stats") or {}
        if stored.get("date") != today:
            stored = {
                "date": today,
                "approve": 0,
                "reject": 0,
                "failed": 0,
                "skipped_no_cookie": 0,
            }
        return stored

    def _increment_stat(self, key: str):
        if key not in ("approve", "reject", "failed", "skipped_no_cookie"):
            return
        self.stats[key] = int(self.stats.get(key, 0) or 0) + 1
        daily = self._get_daily_stats()
        daily[key] = int(daily.get(key, 0) or 0) + 1
        self.plugin.save_data("daily_review_stats", daily)
        self.plugin.save_data("review_health_stats", self.stats)

    def get_today_review_stats(self) -> Dict[str, int]:
        stats = self._get_daily_stats()
        self.plugin.save_data("daily_review_stats", stats)
        return {
            "approve": int(stats.get("approve", 0) or 0),
            "reject": int(stats.get("reject", 0) or 0),
            "failed": int(stats.get("failed", 0) or 0),
            "skipped_no_cookie": int(stats.get("skipped_no_cookie", 0) or 0),
        }

    def _parse_ts(self, ts: Optional[str]) -> Optional[datetime]:
        if not ts:
            return None
        try:
            return datetime.fromisoformat(ts)
        except Exception:
            return None

    def _cleanup_skip_history(self):
        now = datetime.now()
        changed = False
        for app_id, info in list(self.skip_history.items()):
            ts = self._parse_ts((info or {}).get("timestamp"))
            if not ts or now - ts >= timedelta(hours=self.SKIP_CACHE_HOURS):
                self.skip_history.pop(app_id, None)
                changed = True
        if changed:
            self.plugin.save_data("skip_history", self.skip_history)

    def _should_bypass_application(self, app_id: Any) -> bool:
        entry = self.skip_history.get(app_id)
        if not entry:
            return False
        ts = self._parse_ts(entry.get("timestamp"))
        if not ts:
            self.skip_history.pop(app_id, None)
            self.plugin.save_data("skip_history", self.skip_history)
            return False
        elapsed = datetime.now(ts.tzinfo) - ts
        if elapsed < timedelta(hours=self.SKIP_CACHE_HOURS):
            sites = entry.get("sites") or []
            logger.info(
                "申请 %s 在 %s 因缺少站点匹配或 Cookie 已跳过，48 小时内不重复审核。缺失站点=%s",
                app_id,
                ts.isoformat(),
                ",".join(sites) if sites else "未知",
            )
            return True
        self.skip_history.pop(app_id, None)
        self.plugin.save_data("skip_history", self.skip_history)
        return False

    # --- 锁定管理 ---
    def _cleanup_lock_tracker(self):
        """移除超过 48 小时的陈旧锁记录，避免无限重试。"""
        now = datetime.now()
        changed = False
        for app_id, info in list(self.lock_tracker.items()):
            ts = self._parse_ts((info or {}).get("first_locked_at"))
            if ts and now - ts >= timedelta(hours=self.SKIP_CACHE_HOURS):
                self.lock_tracker.pop(app_id, None)
                changed = True
        if changed:
            self.plugin.save_data("lock_tracker", self.lock_tracker)

    def _cleanup_lock_blacklist(self):
        now = datetime.now()
        changed = False
        for app_id, info in list(self.lock_blacklist.items()):
            ts = self._parse_ts((info or {}).get("timestamp"))
            if not ts or now - ts >= timedelta(hours=self.SKIP_CACHE_HOURS):
                self.lock_blacklist.pop(app_id, None)
                changed = True
        if changed:
            self.plugin.save_data("lock_blacklist", self.lock_blacklist)

    def _is_lock_blacklisted(self, app_id: Any) -> bool:
        entry = self.lock_blacklist.get(app_id)
        if not entry:
            return False
        ts = self._parse_ts(entry.get("timestamp"))
        if not ts:
            self.lock_blacklist.pop(app_id, None)
            self.plugin.save_data("lock_blacklist", self.lock_blacklist)
            return False
        if datetime.now(ts.tzinfo) - ts < timedelta(hours=self.SKIP_CACHE_HOURS):
            logger.warning("申请 %s 因重复锁定失败已加入黑名单，48 小时内不再处理", app_id)
            return True
        self.lock_blacklist.pop(app_id, None)
        self.plugin.save_data("lock_blacklist", self.lock_blacklist)
        return False

    def _record_lock(self, app_id: Any):
        info = self.lock_tracker.get(app_id) or {}
        info.setdefault("first_locked_at", datetime.now().isoformat())
        info["attempts"] = int(info.get("attempts") or 0)
        info["last_attempt_at"] = datetime.now().isoformat()
        self.lock_tracker[app_id] = info
        self.plugin.save_data("lock_tracker", self.lock_tracker)

    def _mark_lock_attempt(self, app_id: Any):
        info = self.lock_tracker.get(app_id) or {"first_locked_at": datetime.now().isoformat()}
        info["attempts"] = int(info.get("attempts") or 0) + 1
        info["last_attempt_at"] = datetime.now().isoformat()
        self.lock_tracker[app_id] = info
        self.plugin.save_data("lock_tracker", self.lock_tracker)

    def _clear_lock_record(self, app_id: Any):
        if app_id in self.lock_tracker:
            self.lock_tracker.pop(app_id, None)
            self.plugin.save_data("lock_tracker", self.lock_tracker)

    def _force_unlock_and_blacklist(self, app_id: Any, remark: str):
        logger.warning("申请 %s 连续尝试仍被锁定，将强制解锁并加入黑名单", app_id)
        self.unlock_application(app_id, remark)
        self.lock_blacklist[app_id] = {"timestamp": datetime.now().isoformat(), "remark": remark}
        self.plugin.save_data("lock_blacklist", self.lock_blacklist)
        self._clear_lock_record(app_id)

    def _after_lock_attempt(self, app_id: Any, success: bool):
        if success:
            self._clear_lock_record(app_id)
            return
        info = self.lock_tracker.get(app_id) or {}
        attempts = int(info.get("attempts") or 0)
        if attempts >= 2:
            self._force_unlock_and_blacklist(app_id, "连续两次续审失败，自动解锁")

    # --- 通用请求 ---
    def _api_client(self) -> RequestUtils:
        headers = {"Authorization": f"Bearer {self.config_mgr.api_token}", "Content-Type": "application/json"}
        return RequestUtils(headers=headers, timeout=30, proxies=self.config_mgr.api_proxies)

    def _api_try(self, method: str, path: str, retries: int = 3, interval: int = 15, **kwargs):
        """
        统一的 API 调用重试封装。默认重试 3 次，间隔 15 秒。
        返回最后一次响应。
        """
        res = None
        url = self._full_url(path)
        client = self._api_client()
        for idx in range(retries):
            try:
                if method == "get":
                    res = client.get_res(url, **kwargs)
                else:
                    res = client.post_res(url, **kwargs)
            except Exception as exc:
                logger.error("API 请求异常 %s %s: %s", method.upper(), url, exc)
                res = None
            if res and res.status_code == 200:
                return res
            if idx < retries - 1:
                time.sleep(interval)
        return res

    def _full_url(self, path: str) -> str:
        return f"{self.config_mgr.api_base.rstrip('/')}{path}"

    def _store_heartbeat(self, payload: Dict[str, Any], error: Optional[str] = None):
        """记录心跳/状态汇报的最新结果并保留已有字段。"""
        existing = self.plugin.get_data("heartbeat_status") or {}
        merged = dict(existing)
        if payload:
            merged.update({k: v for k, v in payload.items() if v is not None})
        merged["updated_at"] = datetime.now().isoformat()
        if error:
            merged["error"] = error
        else:
            merged.pop("error", None)
        self.plugin.save_data("heartbeat_status", merged)

    # --- 上游 API ---
    def sync_remote_config(self):
        logger.debug("开始同步审核系统配置")
        if not self.config_mgr.api_token:
            logger.warning("未配置 API Token，无法同步审核配置")
            return
        if not self.config_mgr.should_sync_remote():
            logger.debug("配置同步跳过：未到同步间隔")
            return
        try:
            res = self._api_try("get", "/api/v1/site-verifications/config")
            if res and res.status_code == 200:
                data = res.json() or {}
                if str(data.get("ret")) == "0":
                    self.config_mgr.update_remote_cache(data.get("data") or {})
                    logger.info("审核系统配置同步成功")
                else:
                    logger.error("同步审核配置失败：ret=%s, msg=%s", data.get("ret"), data.get("msg"))
            else:
                logger.error("同步审核配置失败，HTTP 状态码：%s", res.status_code if res else "无响应")
        except Exception as exc:
            logger.error("同步审核配置异常: %s", exc)

    def fetch_pending(self, statuses: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        targets = statuses or ["none"]
        collected: Dict[Any, Dict[str, Any]] = {}
        for status in targets:
            logger.debug("开始获取待审核列表(auto_status=%s)", status)
            query = {"auto_status": status, "page": 1, "per_page": 50}
            res = self._api_try("get", "/api/v1/site-verifications", params=query)
            if not res or res.status_code != 200:
                logger.error("获取待审核列表失败，HTTP 状态码：%s", res.status_code if res else "无响应")
                continue
            try:
                payload = res.json()
            except Exception as exc:
                logger.error("解析待审核列表失败: %s", exc)
                continue
            if str(payload.get("ret")) != "0":
                logger.error("获取待审核列表返回错误：%s", payload.get("msg"))
                continue
            data_list = payload.get("data", {}).get("data") or []
            for item in data_list:
                app_id = item.get("id")
                if app_id is not None:
                    collected[app_id] = item
        logger.info("获取待审核列表成功，数量=%s", len(collected))
        return list(collected.values())

    def fetch_logs(self):
        logger.debug("开始获取审核日志")
        if not self.config_mgr.should_fetch_logs():
            logger.debug("获取审核日志跳过：未到刷新间隔")
            return
        res = self._api_try("get", "/api/v1/site-verifications/logs")
        if not res or res.status_code != 200:
            logger.error("获取审核日志失败：HTTP %s", res.status_code if res else "无响应")
            return
        try:
            payload = res.json()
            if str(payload.get("ret")) == "0":
                self.plugin.save_data("review_logs", payload.get("data") or [])
                self.config_mgr.record_log_fetch()
                logger.info("审核日志拉取成功，条数=%s", len(payload.get("data") or []))
        except Exception as exc:
            logger.error("解析审核日志失败: %s", exc)

    def lock_application(self, app_id: Any) -> bool:
        res = self._api_try("post", f"/api/v1/site-verifications/{app_id}/lock", retries=3)
        if not res or res.status_code != 200:
            logger.error("申请 %s 加锁 HTTP 失败：%s", app_id, res.status_code if res else "无响应")
            return False
        try:
            payload = res.json()
        except Exception:
            logger.error("申请 %s 加锁响应解析失败", app_id)
            return False
        if str(payload.get("ret")) == "0":
            logger.info("申请 %s 加锁成功", app_id)
            return True
        logger.error("申请 %s 加锁返回失败：%s", app_id, payload.get("msg"))
        return False

    def unlock_application(self, app_id: Any, remark: str):
        body = {"remark": self._trim_remark(remark)}
        for idx in range(5):
            try:
                res = self._api_try("post", f"/api/v1/site-verifications/{app_id}/unlock", retries=1, json=body)
                if not res:
                    logger.error("申请 %s 解锁失败：无响应", app_id)
                elif res.status_code != 200:
                    logger.error("申请 %s 解锁失败：HTTP %s", app_id, res.status_code)
                else:
                    payload = res.json()
                    if str(payload.get("ret")) == "0":
                        logger.info("申请 %s 解锁成功", app_id)
                        return True
                    logger.error("解锁申请 %s 失败：%s", app_id, payload.get("msg"))
            except Exception as exc:
                logger.error("解锁申请 %s 时异常: %s", app_id, exc)
            if idx < 4:
                time.sleep(15)
        return False

    def update_status(self, app_id: Any, action: str, remark: str) -> bool:
        payload = {"action": action, "remark": self._trim_remark(remark)}
        retries = 5
        interval = 15
        for idx in range(retries):
            res = self._api_try("post", f"/api/v1/site-verifications/{app_id}/status", retries=1, json=payload)
            if not res or res.status_code != 200:
                logger.error("状态更新失败(HTTP) #%s/%s：%s", idx + 1, retries, res.status_code if res else "无响应")
            else:
                try:
                    data = res.json()
                    if str(data.get("ret")) == "0":
                        return True
                    logger.warning("状态更新返回错误 #%s/%s：%s", idx + 1, retries, data.get("msg"))
                except Exception as exc:
                    logger.error("解析状态更新响应失败：%s", exc)
            if idx < retries - 1:
                time.sleep(interval)
        logger.error("申请 %s 状态更新最终失败，action=%s", app_id, action)
        return False

    # --- 核心流程 ---
    def run_review(self):
        if self.running:
            logger.warning("自动审核任务仍在运行，跳过本轮")
            return
        if not self.config_mgr.enabled:
            logger.debug("自动审核跳过：插件未启用")
            return
        if not self.config_mgr.api_token:
            logger.warning("未配置 API Token，自动审核停止")
            return
        test_url = self.config_mgr.should_run_test_parse()
        if test_url:
            self._run_test_parse(test_url)

        if not self.config_mgr.auto_review_enabled_remote:
            logger.info("远端关闭自动审核，保留检测任务")
            return
        self.running = True
        try:
            logger.info("自动审核任务开始")
            self.sync_remote_config()
            self.registry.refresh()
            apps = self.fetch_pending(statuses=["processing", "none", "failed"])
            # 将已知自身锁定的请求提前处理
            apps = sorted(apps, key=lambda a: 0 if a.get("id") in self.lock_tracker else 1)
            for app in apps:
                app_id = app.get("id")
                if self._is_lock_blacklisted(app_id):
                    continue
                resume_locked = app_id in self.lock_tracker
                if (app.get("auto_status") or "").lower() == "processing" and not resume_locked:
                    # 他人锁定的请求，跳过
                    continue
                success = self._process_application(app, resume_locked=resume_locked)
                self._after_lock_attempt(app_id, success)
            self.fetch_logs()
        finally:
            logger.info("自动审核任务结束")
            self.running = False

    def _process_application(self, application: Dict[str, Any], resume_locked: bool = False) -> bool:
        app_id = application.get("id")
        site_accounts = application.get("site_accounts") or []
        target_email = (application.get("target_email") or "").lower()
        target_username = (application.get("target_username") or "").lower()
        if self._is_lock_blacklisted(app_id):
            return False
        if self._should_bypass_application(app_id):
            if resume_locked:
                self.unlock_application(app_id, "续审跳过，释放锁")
                self._clear_lock_record(app_id)
            return False
        skipped_sites = []
        invalid_cookie_sites: List[str] = []
        parse_unready_sites: List[str] = []
        site_results = []
        parse_results = self.plugin.get_data("parse_check_results") or []
        parse_map = {item.get("site_key"): item for item in parse_results if item.get("site_key")}
        cookie_states = self.registry.cookie_status or {}

        # 缺少 Cookie 直接跳过
        for account in site_accounts:
            match = self.registry.match_site_account(account)
            if not match or not match.get("has_cookie"):
                skipped_sites.append(account.get("name") or account.get("site_key"))
                continue
            site_key = account.get("site_key") or account.get("key")
            state = cookie_states.get(site_key) or {}
            if not (state.get("matched") and state.get("valid")):
                reason = state.get("reason") or "Cookie 未通过检测"
                invalid_cookie_sites.append(f"{account.get('name') or site_key}({reason})")
                continue
            parse_res = parse_map.get(site_key) or {}
            parse_status = (parse_res.get("status") or "").lower()
            if parse_status not in ("success", "partial"):
                parse_reason = parse_res.get("reason") or "解析未通过"
                parse_unready_sites.append(f"{account.get('name') or site_key}({parse_reason})")
        if skipped_sites:
            self._increment_stat("skipped_no_cookie")
            self.skip_history[app_id] = {
                "sites": skipped_sites,
                "timestamp": datetime.now().isoformat(),
            }
            self.plugin.save_data("skip_history", self.skip_history)
            logger.warning(
                "申请 %s 缺少站点匹配或 Cookie，跳过并缓存 48 小时，缺失站点=%s", app_id, ",".join(skipped_sites)
            )
            return False
        if invalid_cookie_sites or parse_unready_sites:
            self._increment_stat("skipped_no_cookie")
            logger.warning(
                "申请 %s 跳过：Cookie/解析检测未通过，Cookie=%s，解析=%s",
                app_id,
                ",".join(invalid_cookie_sites) if invalid_cookie_sites else "无",
                ",".join(parse_unready_sites) if parse_unready_sites else "无",
            )
            return False

        # 锁定
        locked = True
        if resume_locked:
            if app_id not in self.lock_tracker:
                self._record_lock(app_id)
        else:
            locked = self.lock_application(app_id)
            if locked:
                self._record_lock(app_id)
        if not locked:
            logger.error("申请 %s 加锁失败，跳过", app_id)
            return False
        self._mark_lock_attempt(app_id)

        try:
            for account in site_accounts:
                site_result = self._review_site(application, account, target_username, target_email)
                site_results.append(site_result)
                if site_result.get("error"):
                    break

            decision = self._decide(application, site_results)
            if decision["action"] == "unlock":
                unlocked = self.unlock_application(app_id, decision["remark"])
                if unlocked:
                    self._clear_lock_record(app_id)
                self._increment_stat("failed")
                self._notify_exception(application, decision["remark"])
                return False
            else:
                ok = self.update_status(app_id, decision["action"], decision["remark"])
                if ok:
                    if decision["action"] == "approve":
                        self._increment_stat("approve")
                    elif decision["action"] == "reject":
                        self._increment_stat("reject")
                    logger.info("申请 %s 状态提交成功：%s", app_id, decision["action"])
                    if self.config_mgr.config.get("notify_review_result", True):
                        self._notify_review_result(application, decision, site_results)
                    self._clear_lock_record(app_id)
                    return True
                else:
                    unlocked = self.unlock_application(app_id, "审核结果已生成但状态更新失败，请人工处理。")
                    if unlocked:
                        self._clear_lock_record(app_id)
                    self._increment_stat("failed")
                    self._notify_exception(application, "调用 /status 失败，已自动解锁")
                    return False
        except Exception as exc:
            logger.error("处理申请 %s 时异常：%s", app_id, exc)
            unlocked = self.unlock_application(app_id, f"自动审核失败: {exc}")
            if unlocked:
                self._clear_lock_record(app_id)
            self._increment_stat("failed")
            self._notify_exception(application, f"自动审核异常：{exc}")
        finally:
            logger.info("申请 %s 处理结束", app_id)
        return False

    def report_client_status(self):
        """定期向审核系统汇报本地站点状态。"""
        if not self.config_mgr.enabled:
            logger.debug("客户端状态汇报跳过：插件未启用")
            return
        if not self.config_mgr.api_token:
            logger.warning("未配置 API Token，客户端状态汇报停止")
            return
        if not self.registry:
            logger.warning("站点注册表未初始化，跳过状态汇报")
            return
        try:
            self.registry.refresh()
        except Exception as exc:
            logger.error("刷新站点映射失败，跳过状态汇报：%s", exc)
            return

        parse_results = self.plugin.get_data("parse_check_results") or []
        parse_map = {item.get("site_key"): item for item in parse_results if item.get("site_key")}

        all_keys = (
            set(self.registry.site_mapping.keys())
            | set(self.registry.cookie_status.keys())
            | set(parse_map.keys())
        )
        if not all_keys:
            logger.debug("客户端状态汇报跳过：无站点数据")
            return

        now_iso = datetime.now().isoformat()
        items = []
        for key in sorted(all_keys):
            site_info = self.registry.site_mapping.get(key) or {}
            cookie_cache = self.registry.cookie_status.get(key) or {}
            parse_cache = parse_map.get(key) or {}
            matched = cookie_cache.get("matched")
            if matched is None:
                matched = bool(site_info.get("local"))
            valid = cookie_cache.get("valid")
            cookie_reason = (cookie_cache.get("reason") or "").strip()
            parse_reason = (parse_cache.get("reason") or "").strip()
            if matched is False:
                cookie_status_val = "unmatched"
                if not cookie_reason:
                    cookie_reason = "本地未匹配站点"
            elif valid is True:
                cookie_status_val = "ok"
            elif valid is False:
                cookie_status_val = "cookie_invalid"
                if not cookie_reason:
                    cookie_reason = "Cookie 无效"
            else:
                cookie_status_val = "unknown"
                if not cookie_reason:
                    cookie_reason = "尚未检测"

            raw_parse_status = (parse_cache.get("status") or "").lower()
            if raw_parse_status == "failed":
                parse_status_val = "failed"
            elif raw_parse_status in ("success", "partial"):
                parse_status_val = "ok"
            else:
                parse_status_val = "unknown"

            checked_at_candidates = [
                parse_cache.get("checked_at"),
                cookie_cache.get("checked_at"),
                now_iso,
            ]
            checked_at = next((ts for ts in checked_at_candidates if ts), now_iso)

            reasons = []
            if cookie_reason:
                reasons.append(f"Cookie: {cookie_reason}")
            if parse_reason and parse_status_val != "unknown":
                reasons.append(f"解析: {parse_reason}")
            if not reasons and cookie_status_val == "unknown" and parse_status_val == "unknown":
                reasons.append("尚未检测")
            reason = "；".join(reasons)
            if len(reason) > 1000:
                reason = reason[:1000]

            status_detail = {
                "cookie": cookie_status_val,
                "parse": parse_status_val,
            }
            if cookie_status_val in ("unknown", "unmatched"):
                status_detail["other"] = cookie_status_val
            items.append(
                {
                    "site_key": key,
                    "status": cookie_status_val,
                    "reason": reason,
                    "checked_at": checked_at,
                    "cookie_status": cookie_status_val,
                    "parse_status": parse_status_val,
                    "status_detail": status_detail,
                }
            )

        payload: Dict[str, Any] = {"items": items}
        client_version = str(getattr(self.plugin, "plugin_version", "") or "").strip()
        if client_version:
            payload["client_version"] = client_version[:64]
        # 附带本地配置（去除敏感 Token），便于审核端了解客户端参数
        safe_config = {}
        try:
            safe_config = {k: v for k, v in (self.config_mgr.config or {}).items() if k not in ("api_token",)}
        except Exception:
            safe_config = {}
        if safe_config:
            payload["client_config"] = safe_config

        try:
            res = self._api_try("post", "/api/v1/site-verifications/client-status", json=payload)
        except Exception as exc:
            self._store_heartbeat({}, error=f"状态汇报请求异常: {exc}")
            logger.error("客户端状态汇报异常：%s", exc)
            return

        if not res:
            self._store_heartbeat({}, error="状态汇报失败: 无响应")
            logger.error("客户端状态汇报失败：无响应")
            return
        if res.status_code != 200:
            self._store_heartbeat({}, error=f"状态汇报失败: HTTP {res.status_code}")
            logger.error("客户端状态汇报失败，HTTP 状态码：%s", res.status_code)
            return
        try:
            data = res.json()
        except Exception as exc:
            self._store_heartbeat({}, error=f"状态汇报解析失败: {exc}")
            logger.error("解析客户端状态汇报响应失败: %s", exc)
            return

        if str(data.get("ret")) == "0":
            body_data = data.get("data") or {}
            report_record = {"reported_at": now_iso, "items": items, "response": body_data}
            self.plugin.save_data("client_status_report", report_record)
            last_reported = body_data.get("last_reported_at") or now_iso
            self._store_heartbeat({"last_reported_at": last_reported})
            logger.info("客户端状态汇报成功，站点数=%s", len(items))
        else:
            msg = data.get("msg") or "未知错误"
            self._store_heartbeat({}, error=f"状态汇报失败: {msg}")
            logger.error("客户端状态汇报返回错误：%s", msg)

    def send_heartbeat(self):
        """定期上报心跳并记录在线状态。"""
        if not self.config_mgr.enabled:
            logger.debug("心跳跳过：插件未启用")
            return
        if not self.config_mgr.api_token:
            logger.warning("未配置 API Token，心跳停止")
            return
        payload: Dict[str, Any] = {}
        client_version = str(getattr(self.plugin, "plugin_version", "") or "").strip()
        if client_version:
            payload["client_version"] = client_version[:64]
        try:
            res = self._api_try("post", "/api/v1/site-verifications/heartbeat", json=payload)
        except Exception as exc:
            self._store_heartbeat({}, error=f"心跳请求异常: {exc}")
            logger.error("心跳请求异常：%s", exc)
            return

        if not res:
            self._store_heartbeat({}, error="心跳失败: 无响应")
            logger.error("心跳请求无响应")
            return
        if res.status_code != 200:
            self._store_heartbeat({}, error=f"心跳失败: HTTP {res.status_code}")
            logger.error("心跳请求失败，HTTP 状态码：%s", res.status_code)
            return
        try:
            data = res.json()
        except Exception as exc:
            self._store_heartbeat({}, error=f"心跳解析失败: {exc}")
            logger.error("解析心跳响应失败: %s", exc)
            return

        if str(data.get("ret")) == "0":
            hb_data = data.get("data") or {}
            if hb_data:
                self._store_heartbeat(hb_data)
            else:
                self._store_heartbeat({"last_heartbeat_at": datetime.now().isoformat()})
            logger.debug("心跳上报成功")
        else:
            msg = data.get("msg") or "未知错误"
            self._store_heartbeat({}, error=f"心跳失败: {msg}")
            logger.warning("心跳返回错误：%s", msg)

    def _run_test_parse(self, url: str):
        """手工测试解析指定链接，仅输出日志。"""
        try:
            logger.info("开始测试解析：url=%s", url)
            cookie = None
            ua = settings.USER_AGENT
            try:
                if self.registry:
                    self.registry.refresh()
                    host = urlparse(url).netloc.lower()
                    match = next(
                        (
                            site
                            for site in self.registry.site_mapping.values()
                            if (site.get("domain") or "").lower() == host
                            or urlparse((site.get("remote") or {}).get("url") or "").netloc.lower() == host
                        ),
                        None,
                    )
                    if match and match.get("local"):
                        cookie = match["local"].get("cookie")
                        ua = match["local"].get("ua") or ua
            except Exception:
                pass
            headers = {"User-Agent": ua}
            if cookie:
                headers["Cookie"] = cookie

            req = RequestUtils(headers=headers, timeout=30)
            res = None
            for _ in range(5):
                res = req.get_res(url, allow_redirects=True, verify=False)
                if res and res.status_code == 200:
                    break
                time.sleep(1)
            if not res or res.status_code != 200:
                logger.error("测试解析失败：HTTP %s", res.status_code if res else "无响应")
                return
            parsed = self.parser.parse_page(res.text, overrides={"base_url": url})
            logger.info(
                "测试解析完成 用户=%s 邮箱=%s 等级=%s 注册时间=%s",
                parsed.get("username"),
                parsed.get("email"),
                parsed.get("level_standard") or parsed.get("level_raw"),
                parsed.get("register_time"),
            )
        except Exception as exc:
            logger.error("测试解析异常：%s", exc)

    def _review_site(
        self,
        application: Dict[str, Any],
        account: Dict[str, Any],
        target_username: str,
        target_email: str,
    ) -> Dict[str, Any]:
        site_key = account.get("site_key") or account.get("key")
        verification_url = account.get("verification_url") or ""
        if not verification_url and account.get("query_template") and account.get("uid"):
            verification_url = (account["query_template"] or "").format(account.get("url") or "", account.get("uid"))

        match = self.registry.match_site_account(account) or {}
        local_site = match.get("local") or {}
        cookie = _sanitize_cookie_string(local_site.get("cookie"))
        ua = local_site.get("ua") or settings.USER_AGENT
        logger.debug("开始解析站点 %s，验证链接=%s", site_key, verification_url)
        result = {
            "site_key": site_key,
            "site_name": account.get("name") or site_key,
            "username_match": False,
            "email_match": False,
            "level_ok": False,
            "privacy_level": "mid",
            "error": None,
        }

        if not verification_url:
            result["error"] = "缺少验证链接"
            return result
        try:
            req = RequestUtils(headers={"Cookie": cookie, "User-Agent": ua}, timeout=45)
            res = None
            for idx in range(5):
                res = req.get_res(verification_url, allow_redirects=True, verify=False)
                if res and res.status_code == 200:
                    break
                time.sleep(1)
            if not res:
                result["error"] = "访问失败：无响应"
                return result
            if res.status_code in (301, 302) and "login" in (res.headers.get("Location") or "").lower():
                result["error"] = "Cookie 失效，跳转登录"
                return result
            if res.status_code != 200:
                result["error"] = f"访问失败：HTTP {res.status_code}"
                return result
            parsed = self.parser.parse_page(
                res.text,
                site_key=site_key,
                overrides={
                    **self.config_mgr.parse_rule(site_key),
                    "level_aliases": self.config_mgr.level_aliases(site_key),
                    "base_url": verification_url,
                },
                strip_nav=True,
            )
            result.update(parsed)
            result["username_match"] = bool(
                parsed.get("username") and target_username and parsed["username"].lower() == target_username
            )
            result["email_match"] = bool(
                parsed.get("email") and target_email and parsed["email"].lower() == target_email
            )
            min_level = self.config_mgr.min_user_class
            try:
                min_idx = LEVEL_ORDER.index(min_level) + 1
            except ValueError:
                min_idx = None
            if parsed.get("level_index") and min_idx:
                result["level_ok"] = parsed["level_index"] >= min_idx
            else:
                result["level_ok"] = False
            logger.debug(
                "站点 %s 解析完成 用户匹配=%s 邮箱匹配=%s 等级通过=%s 隐私=%s 注册时间=%s",
                site_key,
                result["username_match"],
                result["email_match"],
                result["level_ok"],
                result["privacy_level"],
                result.get("register_time"),
            )
            return result
        except Exception as exc:
            result["error"] = f"解析异常: {exc}"
            return result

    def _decide(self, application: Dict[str, Any], results: List[Dict[str, Any]]) -> Dict[str, str]:
        has_error = any(r.get("error") for r in results)
        has_privacy_block = any(r.get("privacy_level") in ("high", "mid") for r in results)
        verification_level = self.config_mgr.verification_level
        require_username_match = verification_level == "high"
        username_mismatch = any(not r.get("username_match") for r in results) if require_username_match else False
        email_mismatch = any(not r.get("email_match") for r in results)
        level_issue = any(not r.get("level_ok") for r in results)

        if has_error:
            reason = "; ".join([r.get("error") for r in results if r.get("error")][:3])
            return {"action": "unlock", "remark": f"自动审核失败：{reason}"}
        if has_privacy_block or username_mismatch or email_mismatch or level_issue:
            remark = self._build_reject_remark(results)
            return {"action": "reject", "remark": remark}
        remark = self._build_approve_remark(results, application)
        return {"action": "approve", "remark": remark}

    def _verification_requirement_text(self) -> str:
        level = self.config_mgr.verification_level
        if level == "low":
            return "验证等级：low（仅校验邮箱一致性）"
        return "验证等级：high（校验用户名与邮箱一致性）"

    def _build_approve_remark(self, results: List[Dict[str, Any]], application: Dict[str, Any]) -> str:
        lines = ["✅ 自动审核通过。", self._verification_requirement_text(), "", "站点结果："]

        def _flag(val: bool) -> str:
            return "✅" if val else "❌"

        for item in results:
            lines.extend(
                [
                    f"• {item.get('site_name')}：",
                    f"  - 用户：{item.get('username') or '未知'}",
                    f"  - 邮箱：{item.get('email') or '未知'}",
                    f"  - 等级：{item.get('level_standard') or item.get('level_raw') or '未知'}",
                    f"  - 注册：{item.get('register_time') or '未知'}",
                    f"  - 匹配：U{_flag(item.get('username_match'))} / E{_flag(item.get('email_match'))} / L{_flag(item.get('level_ok'))}",
                    "",
                ]
            )
        if application.get("type") == "invite":
            lines.append("🎟️ 邀请名额将由系统自动扣减并发送邮件。")
        return self._trim_remark("\n".join(lines).rstrip())

    def _build_reject_remark(self, results: List[Dict[str, Any]]) -> str:
        require_username_match = self.config_mgr.verification_level == "high"
        parts = ["❌ 自动审核拒绝。", "您所使用的邀请权限已自动退回。", self._verification_requirement_text(), ""]
        passed_blocks: List[str] = []
        issue_blocks: List[str] = []

        def _flag(val: bool) -> str:
            return "✅" if val else "❌"

        for item in results:
            reasons = []
            if item.get("privacy_level") in ("high", "mid"):
                reasons.append(f"隐私设置过高({item.get('privacy_level')})，请调整为低隐私并确保邮箱可见")
            if require_username_match and not item.get("username_match"):
                reasons.append("用户名不匹配")
            if not item.get("email"):
                reasons.append("邮箱不可见，可能因隐私设置导致，请开启低隐私确保邮箱可见")
            elif not item.get("email_match"):
                reasons.append("检测到邮箱与申请邮箱不符")
            if not item.get("level_ok"):
                reasons.append("等级不达标或无法识别")
            if item.get("error"):
                reasons.append(item["error"])
            block = [
                f"{item.get('site_name')}：",
                f"- 用户：{item.get('username') or '未知'}",
                f"- 邮箱：{item.get('email') or '未知'}",
                f"- 等级：{item.get('level_standard') or item.get('level_raw') or '未知'}",
                f"- 注册：{item.get('register_time') or '未知'}",
                f"- 匹配：U{_flag(item.get('username_match'))} / E{_flag(item.get('email_match'))} / L{_flag(item.get('level_ok'))}",
            ]
            if reasons:
                block.append(f"- 原因：{'；'.join(reasons)}")
                block.append("")
                issue_blocks.extend(block)
            else:
                block.append("- 状态：通过")
                block.append("")
                passed_blocks.extend(block)

        if passed_blocks:
            parts.extend(["✅ 已通过站点："] + passed_blocks)
        if issue_blocks:
            parts.extend(["⚠️ 存在问题："] + issue_blocks)
        text = "\n".join(parts).rstrip()
        return self._trim_remark(text or "信息不匹配")

    def _trim_remark(self, text: str) -> str:
        limit = 1000
        if len(text) > limit:
            return text[: limit - 3] + "..."
        return text

    # --- 通知 ---
    def _notify_review_result(
        self, application: Dict[str, Any], decision: Dict[str, str], results: List[Dict[str, Any]]
    ):
        title = f"审核结果：申请 {application.get('id')} {decision.get('action')}"
        lines = [
            f"申请类型：{application.get('type')}",
            f"目标用户：{application.get('target_username')} / {application.get('target_email')}",
            f"结果：{ '通过' if decision.get('action') == 'approve' else '拒绝' }",
        ]
        if decision.get("action") == "reject":
            lines.append("您所使用的邀请权限已自动退回。")
        lines.append("")
        for item in results:
            lines.append(
                f"{item.get('site_name')}: 用户={item.get('username') or '未知'}, "
                f"邮箱={item.get('email') or '未知'}, 等级={item.get('level_standard') or item.get('level_raw') or '未知'}, "
                f"隐私={item.get('privacy_level')}, 匹配:U={'是' if item.get('username_match') else '否'} "
                f"E={'是' if item.get('email_match') else '否'} L={'是' if item.get('level_ok') else '否'}"
            )
        lines.append("")
        lines.append(decision.get("remark") or "")
        try:
            self.plugin.post_message(
                mtype=NotificationType.SiteMessage,
                title=title,
                text="\n".join(lines),
            )
        except Exception as exc:
            logger.error("发送审核结果通知失败: %s", exc)

    def _notify_exception(self, application: Dict[str, Any], reason: str):
        if not self.config_mgr.config.get("notify_exception", True):
            return
        title = f"审核异常：申请 {application.get('id')}"
        text = (
            f"申请类型：{application.get('type')}\n"
            f"目标用户：{application.get('target_username')} / {application.get('target_email')}\n"
            f"原因：{reason}"
        )
        try:
            self.plugin.post_message(
                mtype=NotificationType.SiteMessage,
                title=title,
                text=text,
            )
        except Exception as exc:
            logger.error("发送异常通知失败: %s", exc)


# ----------------------------
# 插件主体
# ----------------------------
class LuckPTAutoReview(_PluginBase):
    plugin_name = "LuckPT自动审核"
    plugin_desc = "根据审核系统 API 自动匹配站点并提交审核结果。"
    plugin_icon = "https://raw.githubusercontent.com/Abel-j/MoviePilot-Plugins/main/icons/LuckPT.png"
    plugin_version = "3.1.5"
    plugin_author = "LuckPT"
    author_url = "https://pt.luckpt.de/"
    plugin_config_prefix = "luckptautoreview_"
    plugin_order = 31
    auth_level = 2

    def __init__(self):
        super().__init__()
        self.config_mgr: Optional[ConfigManager] = None
        self.sites_helper = SitesHelper()
        self.registry: Optional[SiteRegistry] = None
        self.parser: Optional[ParserEngine] = None
        self.review_engine: Optional[ReviewEngine] = None
        self.scheduler: Optional[BackgroundScheduler] = None

    # -------------- 生命周期 --------------
    def init_plugin(self, config: dict = None):
        logger.info("初始化 LuckPTAutoReview 插件开始")
        self.stop_service()
        self.config_mgr = ConfigManager(self, config)
        self.registry = SiteRegistry(self, self.config_mgr, self.sites_helper)
        self.parser = ParserEngine(self.config_mgr)
        self.review_engine = ReviewEngine(self, self.config_mgr, self.registry, self.parser)

        # 保存后若填写了测试解析 URL，立即执行一次并清空配置
        test_url = self.config_mgr.should_run_test_parse()
        if test_url:
            try:
                self.review_engine._run_test_parse(test_url)
            finally:
                self.config_mgr.update_config({"test_parse_url": ""})

        if not self.config_mgr.enabled:
            logger.warning("插件配置 disabled，跳过任务调度与定时启动")
            return

        # 首次安装启用后，自动执行一次 Cookie 检测与解析检测
        if not self.get_data("first_run_completed"):
            try:
                logger.info("首次启用，自动执行 Cookie 与解析检测")
                self.review_engine.sync_remote_config()
                self.registry.refresh()
                self.registry.run_cookie_check()
                self._parse_check_task()
            except Exception as exc:
                logger.error("首次启用自动检测失败：%s", exc)
            finally:
                self.save_data("first_run_completed", True)

        self.scheduler = BackgroundScheduler(timezone=settings.TZ)
        # 自动审核
        try:
            cron = CronTrigger.from_crontab(self.config_mgr.review_cron)
            self.scheduler.add_job(self.review_engine.run_review, cron, id="luckpt_review", name="自动审核任务")
            logger.info("已注册自动审核任务 cron=%s", self.config_mgr.review_cron)
        except Exception as exc:
            logger.error("添加自动审核 Cron 失败：%s", exc)

        # 配置同步
        self.scheduler.add_job(
            self.review_engine.sync_remote_config,
            "interval",
            minutes=self.config_mgr.config_sync_interval,
            id="luckpt_config_sync",
            name="审核配置同步",
        )
        logger.info("已注册配置同步任务，间隔=%s分钟", self.config_mgr.config_sync_interval)
        # Cookie 检测
        self.scheduler.add_job(
            self.registry.run_cookie_check,
            "interval",
            minutes=self.config_mgr.cookie_check_interval,
            id="luckpt_cookie_check",
            name="Cookie 有效性检测",
        )
        logger.info("已注册Cookie检测任务，间隔=%s分钟", self.config_mgr.cookie_check_interval)
        # 解析检测
        self.scheduler.add_job(
            self._parse_check_task,
            "interval",
            minutes=self.config_mgr.cookie_check_interval,
            id="luckpt_parse_check",
            name="解析检测",
        )
        logger.info("已注册解析检测任务，间隔=%s分钟", self.config_mgr.cookie_check_interval)
        # 失败重试（Cookie 失效 & 解析失败）
        self.scheduler.add_job(
            self._retry_failed_checks,
            "interval",
            minutes=10,
            id="luckpt_retry_failed",
            name="失败重试",
        )
        logger.info("已注册失败重试任务，间隔=10分钟")
        # 客户端状态汇报
        self.scheduler.add_job(
            self.review_engine.report_client_status,
            "interval",
            minutes=5,
            id="luckpt_client_status",
            name="客户端状态汇报",
        )
        logger.info("已注册客户端状态汇报任务，间隔=5分钟")
        # 心跳检测
        self.scheduler.add_job(
            self.review_engine.send_heartbeat,
            "interval",
            minutes=1,
            id="luckpt_heartbeat",
            name="心跳检测",
        )
        logger.info("已注册心跳任务，间隔=1分钟")
        # 每日统计报表
        if self.config_mgr.daily_report_cron:
            try:
                report_cron = CronTrigger.from_crontab(self.config_mgr.daily_report_cron)
                self.scheduler.add_job(
                    self._send_daily_report,
                    report_cron,
                    id="luckpt_daily_report",
                    name="每日统计报表",
                )
                logger.info("已注册每日统计报表任务，cron=%s", self.config_mgr.daily_report_cron)
            except Exception as exc:
                logger.error("添加每日统计报表 Cron 失败：%s", exc)
        # 一次性任务
        if self.config_mgr.config.get("run_cookie_check_once"):
            self.scheduler.add_job(
                self._wrap_once(self.registry.run_cookie_check, "run_cookie_check_once"),
                "date",
                run_date=datetime.now() + timedelta(seconds=3),
                id="luckpt_cookie_once",
                name="一次性 Cookie 检测",
            )
            logger.info("已注册一次性 Cookie 检测任务")
        if self.config_mgr.config.get("run_parse_check_once"):
            self.scheduler.add_job(
                self._wrap_once(self._parse_check_task, "run_parse_check_once"),
                "date",
                run_date=datetime.now() + timedelta(seconds=3),
                id="luckpt_parse_once",
                name="一次性解析检测",
            )
            logger.info("已注册一次性解析检测任务")

        if self.scheduler.get_jobs():
            self.scheduler.start()
            logger.info("LuckPT 定时任务启动完成，已注册 %s 个任务", len(self.scheduler.get_jobs()))
        logger.info("初始化 LuckPTAutoReview 插件结束")

    def stop_service(self):
        if self.scheduler:
            try:
                logger.info("停止 LuckPT 定时任务调度开始")
                self.scheduler.remove_all_jobs()
                self.scheduler.shutdown(wait=False)
                logger.info("停止 LuckPT 定时任务调度完成")
            except Exception:
                pass
            finally:
                self.scheduler = None

    def get_state(self) -> bool:
        return bool(self.config_mgr and self.config_mgr.enabled)

    # -------------- 任务包装 --------------
    def _wrap_once(self, func, flag_key: str):
        def inner():
            try:
                func()
            finally:
                self.config_mgr.clear_oneoff_flag(flag_key)

        return inner

    @staticmethod
    def _fetch_with_retry(req: RequestUtils, url: str, attempts: int = 5, delay: float = 1.0) -> Optional[Any]:
        """统一的带重试 GET 请求。"""
        for idx in range(attempts):
            res = req.get_res(url, allow_redirects=True, verify=False)
            if res and res.status_code == 200:
                return res
            time.sleep(delay)
        return None

    def _parse_check_one(self, key: str, site: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """单站点解析检测，供全量检测与失败重试复用。"""
        if not self.registry:
            logger.debug("解析检测跳过：站点=%s Registry 未初始化", key)
            return None
        cookie_state = (self.registry.cookie_status or {}).get(key) or {}
        if not (cookie_state.get("matched") and cookie_state.get("valid")):
            logger.debug("解析检测跳过：站点=%s Cookie 未通过检测", key)
            return None
        if not site.get("local") or not site.get("local", {}).get("cookie"):
            logger.debug("解析检测跳过：站点=%s 缺少本地配置或 Cookie", key)
            return None
        base_url = (site.get("remote") or {}).get("url") or site.get("local", {}).get("url")
        if not base_url:
            logger.debug("解析检测跳过：站点=%s 缺少 URL", key)
            return None
        try:
            cookie_val = _sanitize_cookie_string(site["local"].get("cookie"))
            req = RequestUtils(
                headers={"Cookie": cookie_val, "User-Agent": site["local"].get("ua")},
                timeout=30,
            )
            res = self._fetch_with_retry(req, base_url, attempts=5)
            if not res or res.status_code != 200:
                logger.debug(
                    "解析检测失败：站点=%s HTTP=%s",
                    key,
                    res.status_code if res else "无响应",
                )
                return {
                    "site_key": key,
                    "site_name": (site.get("remote") or {}).get("name") or key,
                    "status": "failed",
                    "reason": f"访问失败 {res.status_code if res else '无响应'}",
                    "checked_at": datetime.now().isoformat(),
                }
            parsed = self.parser.parse_page(
                res.text,
                site_key=key,
                overrides={
                    **self.config_mgr.parse_rule(key),
                    "level_aliases": self.config_mgr.level_aliases(key),
                    "base_url": base_url,
                },
                strip_nav=False,
            )
            if (not parsed.get("email") or not parsed.get("level_standard")):
                profile_url = parsed.get("profile_url")
                if not profile_url:
                    cookie_str = site.get("local", {}).get("cookie") or ""
                    m_uid = re.search(r"(?:uid|c_secure_uid)=([0-9]+)", cookie_str, re.IGNORECASE)
                    if m_uid and base_url:
                        profile_url = urljoin(base_url, f"/userdetails.php?id={m_uid.group(1)}")
                if profile_url:
                    logger.debug("解析检测二次解析个人主页：站点=%s url=%s", key, profile_url)
                    res_profile = self._fetch_with_retry(req, profile_url, attempts=5)
                    if res_profile and res_profile.status_code == 200:
                        parsed_profile = self.parser.parse_page(
                            res_profile.text,
                            site_key=key,
                            overrides={
                                **self.config_mgr.parse_rule(key),
                                "level_aliases": self.config_mgr.level_aliases(key),
                                "base_url": profile_url,
                            },
                            strip_nav=False,
                        )
                        for k in (
                            "username",
                            "email",
                            "level_raw",
                            "level_standard",
                            "level_index",
                            "privacy_level",
                            "register_time",
                        ):
                            if parsed_profile.get(k):
                                parsed[k] = parsed_profile[k]
            has_username = bool(parsed.get("username"))
            has_email = bool(parsed.get("email"))
            has_level = bool(parsed.get("level_standard") or parsed.get("level_raw"))
            has_standard_level = bool(parsed.get("level_standard"))
            has_register = bool(parsed.get("register_time"))
            missing_fields = []
            if not has_email:
                missing_fields.append("邮箱")
            if not has_level:
                missing_fields.append("等级")
            elif not has_standard_level:
                missing_fields.append("标准等级")
            if not has_register:
                missing_fields.append("注册时间")
            if not has_username:
                status_val = "failed"
                reason_text = "缺少用户名"
            elif missing_fields:
                status_val = "partial"
                reason_text = f"缺少信息：{'/'.join(missing_fields)}"
            else:
                status_val = "success"
                reason_text = None
            logger.debug(
                "解析检测完成：站点=%s 状态=%s 用户=%s 邮箱=%s 等级=%s 注册时间=%s",
                key,
                status_val,
                parsed.get("username"),
                parsed.get("email"),
                parsed.get("level_standard") or parsed.get("level_raw"),
                parsed.get("register_time"),
            )
            return {
                "site_key": key,
                "site_name": (site.get("remote") or {}).get("name") or key,
                "status": status_val,
                "username": parsed.get("username"),
                "email": parsed.get("email"),
                "level": parsed.get("level_standard") or parsed.get("level_raw"),
                "register_time": parsed.get("register_time"),
                "checked_at": datetime.now().isoformat(),
                "privacy_level": parsed.get("privacy_level"),
                "reason": reason_text,
            }
        except Exception as exc:
            logger.error("解析检测异常：站点=%s 错误=%s", key, exc)
            return {
                "site_key": key,
                "site_name": (site.get("remote") or {}).get("name") or key,
                "status": "failed",
                "reason": f"解析异常: {exc}",
                "checked_at": datetime.now().isoformat(),
            }

    def _retry_failed_parse(self) -> List[Dict[str, Any]]:
        """
        对解析失败的站点（status=failed）按 10 分钟节奏进行补偿重试。
        存疑/partial 视为正常，不参与重试。
        """
        if not self.registry or not self.parser:
            return []
        self.registry.refresh()
        existing = self.get_data("parse_check_results") or []
        mapping = {r.get("site_key"): r for r in existing if r.get("site_key")}
        cookie_states = self.registry.cookie_status or {}

        def _cookie_ok(site_key: str) -> bool:
            state = cookie_states.get(site_key) or {}
            return bool(state.get("matched") and state.get("valid"))

        targets = [k for k, v in mapping.items() if v.get("status") == "failed" and _cookie_ok(k)]
        if not targets:
            return []
        logger.info("开始解析失败重试，站点数=%s", len(targets))
        updates: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_map = {
                executor.submit(self._parse_check_one, key, self.registry.site_mapping.get(key) or {}): key
                for key in targets
            }
            for future in as_completed(future_map):
                key = future_map[future]
                try:
                    res = future.result()
                except Exception as exc:
                    logger.error("解析重试并发任务异常：站点=%s 错误=%s", key, exc)
                    res = {
                        "site_key": key,
                        "site_name": key,
                        "status": "failed",
                        "reason": f"并发重试异常: {exc}",
                        "checked_at": datetime.now().isoformat(),
                    }
                if res:
                    mapping[key] = res
                    updates.append(res)
        self.save_data("parse_check_results", list(mapping.values()))
        recovered = len([r for r in updates if r.get("status") == "success"])
        still_failed = len([r for r in updates if r.get("status") != "success"])
        logger.info("解析失败重试结束：恢复=%s 仍失败=%s 总计=%s", recovered, still_failed, len(updates))
        return updates

    def _retry_failed_checks(self):
        """按 10 分钟重试失败的 Cookie 与解析检测。"""
        cookie_res = self.registry.retry_failed_cookies() if self.registry else []
        parse_res = self._retry_failed_parse()
        if not cookie_res and not parse_res:
            logger.debug("失败重试任务：无需要重试的站点")
        else:
            logger.info(
                "失败重试任务完成：Cookie=%s 条，解析=%s 条",
                len(cookie_res),
                len(parse_res),
            )

    def _parse_check_task(self):
        if not self.registry or not self.parser:
            return
        self.registry.refresh()
        results: List[Dict[str, Any]] = []
        cookie_states = self.registry.cookie_status or {}
        eligible_sites = {
            key: site
            for key, site in self.registry.site_mapping.items()
            if (cookie_states.get(key) or {}).get("matched") and (cookie_states.get(key) or {}).get("valid")
        }
        logger.info("开始解析检测，站点数=%s，Cookie 通过=%s", len(self.registry.site_mapping), len(eligible_sites))
        with ThreadPoolExecutor(max_workers=8) as executor:
            future_to_key = {
                executor.submit(self._parse_check_one, key, site): key for key, site in eligible_sites.items()
            }
            for future in as_completed(future_to_key):
                try:
                    res = future.result()
                except Exception as exc:
                    key = future_to_key[future]
                    logger.error("解析检测并发任务异常：站点=%s 错误=%s", key, exc)
                    res = {
                        "site_key": key,
                        "site_name": key,
                        "status": "failed",
                        "reason": f"并发异常: {exc}",
                        "checked_at": datetime.now().isoformat(),
                    }
                if res:
                    results.append(res)
        self.save_data("parse_check_results", results)
        success_cnt = len([r for r in results if r.get("status") in ("success", "partial")])
        fail_cnt = len([r for r in results if r.get("status") == "failed"])
        logger.info("解析检测结束：成功=%s 失败=%s 总计=%s", success_cnt, fail_cnt, len(results))

    @staticmethod
    def _parse_time_str(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except Exception:
            return None

    @staticmethod
    def _format_time(value: Optional[datetime]) -> str:
        if not value:
            return "-"
        return value.isoformat(timespec="seconds")

    def _summarize_cookie_status(self) -> Tuple[Dict[str, int], str]:
        cookie_status = self.get_data("cookie_status") or {}
        remote_sites = self.config_mgr.remote_sites if self.config_mgr else []
        all_keys = {k for k in cookie_status.keys()}
        all_keys |= {s.get("key") or s.get("site_key") for s in remote_sites if s}
        all_keys.discard(None)
        all_keys.discard("")
        summary = {"valid": 0, "invalid": 0, "unmatched": 0, "unchecked": 0}
        latest_at: Optional[datetime] = None
        for key in all_keys:
            status = cookie_status.get(key) or {}
            matched = status.get("matched")
            valid = status.get("valid")
            checked_at = self._parse_time_str(status.get("checked_at"))
            if checked_at and (latest_at is None or checked_at > latest_at):
                latest_at = checked_at
            if status and matched is False:
                summary["unmatched"] += 1
            elif status and valid is True:
                summary["valid"] += 1
            elif status and valid is False:
                summary["invalid"] += 1
            else:
                summary["unchecked"] += 1
        return summary, self._format_time(latest_at)

    def _summarize_parse_results(self) -> Tuple[Dict[str, int], str]:
        parse_results = self.get_data("parse_check_results") or []
        remote_sites = self.config_mgr.remote_sites if self.config_mgr else []
        all_keys = {item.get("site_key") for item in parse_results if item.get("site_key")}
        all_keys |= {s.get("key") or s.get("site_key") for s in remote_sites if s}
        all_keys.discard(None)
        all_keys.discard("")
        summary = {"success": 0, "partial": 0, "failed": 0, "unchecked": 0}
        latest_at: Optional[datetime] = None
        mapping = {item.get("site_key"): item for item in parse_results if item.get("site_key")}
        for key in all_keys:
            res = mapping.get(key) or {}
            status = (res.get("status") or "").lower()
            checked_at = self._parse_time_str(res.get("checked_at"))
            if checked_at and (latest_at is None or checked_at > latest_at):
                latest_at = checked_at
            if status == "success":
                summary["success"] += 1
            elif status == "partial":
                summary["partial"] += 1
            elif status == "failed":
                summary["failed"] += 1
            else:
                summary["unchecked"] += 1
        return summary, self._format_time(latest_at)

    def _send_daily_report(self):
        if not self.config_mgr or not self.config_mgr.enabled:
            logger.debug("每日统计报表跳过：插件未启用")
            return
        today = datetime.now().strftime("%Y-%m-%d")
        review_stats = {
            "approve": 0,
            "reject": 0,
            "failed": 0,
            "skipped_no_cookie": 0,
        }
        if self.review_engine:
            review_stats = self.review_engine.get_today_review_stats()
        cookie_summary, cookie_time = self._summarize_cookie_status()
        parse_summary, parse_time = self._summarize_parse_results()

        lines = [
            f"日期：{today}",
            "",
            "今日审核：",
            f"- 通过：{review_stats.get('approve', 0)}",
            f"- 拒绝：{review_stats.get('reject', 0)}",
            f"- 跳过：{review_stats.get('skipped_no_cookie', 0)}",
            f"- 异常：{review_stats.get('failed', 0)}",
            "",
            "Cookie 检测（最新一次）：",
            f"- 正常：{cookie_summary.get('valid', 0)}",
            f"- 失效：{cookie_summary.get('invalid', 0)}",
            f"- 未匹配：{cookie_summary.get('unmatched', 0)}",
            f"- 未检测：{cookie_summary.get('unchecked', 0)}",
            f"- 最后检测时间：{cookie_time}",
            "",
            "解析检测（最新一次）：",
            f"- 成功：{parse_summary.get('success', 0)}",
            f"- 存疑：{parse_summary.get('partial', 0)}",
            f"- 失败：{parse_summary.get('failed', 0)}",
            f"- 未检测：{parse_summary.get('unchecked', 0)}",
            f"- 最后检测时间：{parse_time}",
        ]
        try:
            self.post_message(
                mtype=NotificationType.SiteMessage,
                title=f"LuckPT 每日统计报表 {today}",
                text="\n".join(lines),
            )
            logger.info("每日统计报表已推送：%s", today)
        except Exception as exc:
            logger.error("每日统计报表推送失败: %s", exc)

    # -------------- UI：配置 --------------
    def get_form(self) -> Tuple[List[dict], Dict[str, Any]]:
        if not self.config_mgr:
            self.config_mgr = ConfigManager(self, None)

        form = [
            {
                "component": "VForm",
                "content": [
                    {
                        "component": "VCard",
                        "props": {"class": "mb-4", "variant": "tonal"},
                        "content": [
                            {"component": "VCardTitle", "text": "基础配置"},
                            {
                                "component": "VCardText",
                                "content": [
                                    {
                                        "component": "VRow",
                                        "content": [
                                            {
                                                "component": "VCol",
                                                "props": {"cols": 12, "md": 4},
                                                "content": [
                                                    {
                                                        "component": "VSwitch",
                                                        "props": {"model": "enabled", "label": "启用插件"},
                                                    }
                                                ],
                                            },
                                            {
                                                "component": "VCol",
                                                "props": {"cols": 12, "md": 4},
                                                "content": [
                                                    {
                                                        "component": "VTextField",
                                                        "props": {
                                                            "model": "api_base_url",
                                                            "label": "审核系统基地址",
                                                            "placeholder": "https://pt.luckpt.de",
                                                        },
                                                    }
                                                ],
                                            },
                                            {
                                                "component": "VCol",
                                                "props": {"cols": 12, "md": 4},
                                                "content": [
                                                    {
                                                        "component": "VTextField",
                                                        "props": {
                                                            "model": "api_proxy",
                                                            "label": "API 代理（可选）",
                                                            "placeholder": "http://127.0.0.1:7890",
                                                        },
                                                    }
                                                ],
                                            },
                                            {
                                                "component": "VCol",
                                                "props": {"cols": 12, "md": 4},
                                                "content": [
                                                    {
                                                        "component": "VTextField",
                                                        "props": {
                                                            "model": "api_token",
                                                            "label": "审核系统 API Token",
                                                            "type": "password",
                                                            "placeholder": "必填",
                                                        },
                                                    }
                                                ],
                                            },
                                            {
                                                "component": "VCol",
                                                "props": {"cols": 12, "md": 4},
                                                "content": [
                                                    {
                                                        "component": "VCronField",
                                                        "props": {
                                                            "model": "review_cron",
                                                            "label": "审核周期 (Cron)",
                                                            "placeholder": "*/5 * * * *",
                                                        },
                                                    }
                                                ],
                                            },
                                        ],
                                    }
                                ],
                            },
                        ],
                    },
                    {
                        "component": "VCard",
                        "props": {"class": "mb-4", "variant": "tonal"},
                        "content": [
                            {"component": "VCardTitle", "text": "周期与一次性任务"},
                            {
                                "component": "VCardText",
                                "content": [
                                    {
                                        "component": "VRow",
                                        "content": [
                                            {
                                                "component": "VCol",
                                                "props": {"cols": 12, "md": 4},
                                                "content": [
                                                    {
                                                        "component": "VTextField",
                                                        "props": {
                                                            "model": "config_sync_interval_minutes",
                                                            "label": "配置同步间隔(分钟)",
                                                            "type": "number",
                                                        },
                                                    }
                                                ],
                                            },
                                            {
                                                "component": "VCol",
                                                "props": {"cols": 12, "md": 4},
                                                "content": [
                                                    {
                                                        "component": "VTextField",
                                                        "props": {
                                                            "model": "cookie_check_interval_minutes",
                                                            "label": "Cookie 检测间隔(分钟)",
                                                            "type": "number",
                                                        },
                                                    }
                                                ],
                                            },
                                            {
                                                "component": "VCol",
                                                "props": {"cols": 12, "md": 4},
                                                "content": [
                                                    {
                                                        "component": "VTextField",
                                                        "props": {
                                                            "model": "log_refresh_interval_minutes",
                                                            "label": "审核记录刷新间隔(分钟)",
                                                            "type": "number",
                                                        },
                                                    }
                                                ],
                                            },
                                        ],
                                    },
                                    {
                                        "component": "VRow",
                                        "class": "mt-2",
                                        "content": [
                                            {
                                                "component": "VCol",
                                                "props": {"cols": 12, "md": 4},
                                                "content": [
                                                    {
                                                        "component": "VSwitch",
                                                        "props": {
                                                            "model": "run_cookie_check_once",
                                                            "label": "运行一次 Cookie 检测",
                                                        },
                                                    }
                                                ],
                                            },
                                            {
                                                "component": "VCol",
                                                "props": {"cols": 12, "md": 4},
                                                "content": [
                                                    {
                                                        "component": "VSwitch",
                                                        "props": {
                                                            "model": "run_parse_check_once",
                                                            "label": "运行一次解析检测",
                                                        },
                                                    }
                                                ],
                                            },
                                            {
                                                "component": "VCol",
                                                "props": {"cols": 12, "md": 4},
                                                "content": [
                                                    {}
                                                ],
                                            },
                                            {
                                                "component": "VCol",
                                                "props": {"cols": 12, "md": 8},
                                                "content": [
                                                    {
                                                        "component": "VTextField",
                                                        "props": {
                                                            "model": "test_parse_url",
                                                            "label": "测试解析 URL（保存后自动触发一次解析，仅日志输出）",
                                                            "placeholder": "https://example.com/userdetails.php?id=123",
                                                        },
                                                    }
                                                ],
                                            },
                                        ],
                                    },
                                ],
                            },
                        ],
                    },
                    {
                        "component": "VCard",
                        "props": {"class": "mb-4", "variant": "tonal"},
                        "content": [
                            {"component": "VCardTitle", "text": "每日统计报表"},
                            {
                                "component": "VCardText",
                                "content": [
                                    {
                                        "component": "VRow",
                                        "content": [
                                            {
                                                "component": "VCol",
                                                "props": {"cols": 12, "md": 6},
                                                "content": [
                                                    {
                                                        "component": "VCronField",
                                                        "props": {
                                                            "model": "daily_report_cron",
                                                            "label": "报表推送时间 (Cron)",
                                                            "placeholder": "0 23 * * *",
                                                        },
                                                    }
                                                ],
                                            },
                                            {
                                                "component": "VCol",
                                                "props": {"cols": 12, "md": 6},
                                                "content": [
                                                    {
                                                        "component": "VAlert",
                                                        "props": {
                                                            "type": "info",
                                                            "variant": "tonal",
                                                            "text": "留空可禁用，默认每天 23:00 推送当日统计。",
                                                        },
                                                    }
                                                ],
                                            },
                                        ],
                                    }
                                ],
                            },
                        ],
                    },
                    {
                        "component": "VCard",
                        "props": {"class": "mb-4", "variant": "tonal"},
                        "content": [
                            {"component": "VCardTitle", "text": "通知设置"},
                            {
                                "component": "VCardText",
                                "content": [
                                    {
                                        "component": "VRow",
                                        "content": [
                                            {
                                                "component": "VCol",
                                                "props": {"cols": 12, "md": 3},
                                                "content": [
                                                    {
                                                        "component": "VSwitch",
                                                        "props": {
                                                            "model": "notify_review_result",
                                                            "label": "审核结果通知",
                                                        },
                                                    }
                                                ],
                                            },
                                            {
                                                "component": "VCol",
                                                "props": {"cols": 12, "md": 3},
                                                "content": [
                                                    {
                                                        "component": "VSwitch",
                                                        "props": {"model": "notify_exception", "label": "异常通知"},
                                                    }
                                                ],
                                            },
                                            {
                                                "component": "VCol",
                                                "props": {"cols": 12, "md": 3},
                                                "content": [
                                                    {
                                                        "component": "VSwitch",
                                                        "props": {"model": "notify_pending", "label": "待审核提醒"},
                                                    }
                                                ],
                                            },
                                        ],
                                    }
                                ],
                            },
                        ],
                    },
                    {
                        "component": "VCard",
                        "props": {"class": "mb-4", "variant": "tonal"},
                        "content": [
                            {"component": "VCardTitle", "text": "重试策略"},
                            {
                                "component": "VCardText",
                                "content": [
                                    {
                                        "component": "VRow",
                                        "content": [
                                            {
                                                "component": "VCol",
                                                "props": {"cols": 12, "md": 6},
                                                "content": [
                                                    {
                                                        "component": "VTextField",
                                                        "props": {
                                                            "model": "status_retry_count",
                                                            "label": "状态更新重试次数",
                                                            "type": "number",
                                                        },
                                                    }
                                                ],
                                            },
                                            {
                                                "component": "VCol",
                                                "props": {"cols": 12, "md": 6},
                                                "content": [
                                                    {
                                                        "component": "VTextField",
                                                        "props": {
                                                            "model": "status_retry_interval_seconds",
                                                            "label": "状态更新重试间隔(秒)",
                                                            "type": "number",
                                                        },
                                                    }
                                                ],
                                            },
                                        ],
                                    }
                                ],
                            },
                        ],
                    },
                    {
                        "component": "VAlert",
                        "props": {
                            "type": "info",
                            "variant": "tonal",
                            "text": "保存后自动启动任务。Token 仅用于调用审核 API，不会记录完整明文。",
                        },
                    },
                ],
            }
        ]
        config_data = dict(self.config_mgr.config)
        # 使用属性以应用默认值；空串用于关闭定时任务
        config_data["daily_report_cron"] = self.config_mgr.daily_report_cron or ""
        return form, config_data

    # -------------- UI：展示页 --------------
    def get_page(self) -> List[dict]:
        if self.review_engine and self.config_mgr and self.config_mgr.api_token:
            try:
                self.review_engine.fetch_logs()
            except Exception as exc:
                logger.warning("页面加载时拉取审核日志失败：%s", exc)
        if self.registry:
            try:
                self.registry.refresh()
            except Exception as exc:
                logger.warning("页面加载时刷新站点映射失败：%s", exc)
        logs = self.get_data("review_logs") or []
        stats = self.get_data("review_health_stats") or {}
        cookie_status = self.get_data("cookie_status") or {}
        parse_results = self.get_data("parse_check_results") or []
        heartbeat_status = self.get_data("heartbeat_status") or {}
        client_status_report = self.get_data("client_status_report") or {}
        pending_apps = self._fetch_applications(auto_status="none")

        def _fmt_time(value: Any) -> str:
            """Format time string to seconds if present."""
            if not value:
                return "-"
            return str(value)[:19]

        def _log_style(action: str, to_status: Optional[str]) -> Tuple[str, str]:
            act = (action or "").lower()
            status = (to_status or "").lower()
            if act == "status_change":
                if status in ("approved", "passed"):
                    return "mdi-check-circle-outline", "success"
                if status in ("rejected", "failed"):
                    return "mdi-close-circle-outline", "error"
                return "mdi-transition", "primary"
            if "lock" in act:
                return "mdi-lock-outline", "info"
            if "unlock" in act:
                return "mdi-lock-open-variant-outline", "warning"
            return "mdi-note-text-outline", "grey"

        log_timeline_items = []
        for item in logs:
            icon, color = _log_style(item.get("action"), item.get("to_status"))
            payload = item.get("payload") or {}
            remark = payload.get("remark") or json.dumps(payload, ensure_ascii=False)
            log_timeline_items.append(
                {
                    "component": "VTimelineItem",
                    "props": {"dot-color": color, "icon": icon, "size": "small", "elevation": 2},
                    "content": [
                        {
                            "component": "div",
                            "props": {"class": "text-caption text-medium-emphasis"},
                            "text": f"{_fmt_time(item.get('created_at'))} · 申请 {item.get('application_id')}",
                        },
                        {
                            "component": "div",
                            "props": {"class": "font-weight-medium"},
                            "text": f"{item.get('action') or '-'} → {item.get('to_status') or '-'}",
                        },
                        {
                            "component": "div",
                            "props": {"class": "text-body-2 mt-1"},
                            "text": remark,
                        },
                    ],
                }
            )
        if not log_timeline_items:
            log_timeline_items = [{"component": "div", "text": "暂无数据"}]

        last_config_synced = _fmt_time(self.config_mgr.remote_config_ts if self.config_mgr else None)
        last_log_ts = _fmt_time(max([l.get("created_at") for l in logs], default=None))
        remote_site_count = len(self.config_mgr.remote_sites) if self.config_mgr and self.config_mgr.remote_sites else 0
        config_base_url = self.config_mgr.api_base if self.config_mgr else "-"
        verification_level = self.config_mgr.verification_level if self.config_mgr else "-"
        hb_online_raw = heartbeat_status.get("online")
        if isinstance(hb_online_raw, bool):
            hb_online = hb_online_raw
        elif isinstance(hb_online_raw, str):
            hb_online = hb_online_raw.lower() == "true"
        else:
            hb_online = None
        if hb_online is True:
            hb_state_text, hb_state_color = "在线", "success"
        elif hb_online is False:
            hb_state_text, hb_state_color = "离线", "error"
        else:
            hb_state_text, hb_state_color = "未知", "grey"
        hb_last_heartbeat = _fmt_time(heartbeat_status.get("last_heartbeat_at"))
        hb_last_report = _fmt_time(heartbeat_status.get("last_reported_at") or client_status_report.get("reported_at"))
        hb_error = heartbeat_status.get("error")

        remote_sites = self.config_mgr.remote_sites if self.config_mgr else []
        # 如果本地未缓存站点且有 token，强制拉取一次 config
        if not remote_sites and self.review_engine and self.config_mgr and self.config_mgr.api_token:
            self.review_engine.sync_remote_config()
            remote_sites = self.config_mgr.remote_sites if self.config_mgr else []
        remote_keys = {s.get("key") or s.get("site_key") for s in remote_sites if s.get("key") or s.get("site_key")}
        all_site_keys = set(remote_keys)

        # --- 构造 Cookie 卡片数据 ---
        cookie_cards: List[Dict[str, Any]] = []
        for key in sorted(all_site_keys):
            remote = next((s for s in remote_sites if (s.get("key") or s.get("site_key")) == key), {})
            status = cookie_status.get(key, {})
            matched = status.get("matched", False)
            valid = status.get("valid", None)
            if not matched and status:
                state = "未匹配"
                color = "grey"
            elif valid is True:
                state = "正常"
                color = "success"
            elif valid is False:
                state = "失效"
                color = "error"
            else:
                state = "未检测"
                color = "info"
            cookie_cards.append(
                {
                    "site_name": remote.get("name") or key,
                    "site_key": key,
                    "state": state,
                    "color": color,
                    "matched": matched,
                    "valid": valid,
                    "reason": status.get("reason", ""),
                    "checked_at": status.get("checked_at", ""),
                }
            )
        cookie_grouped = {
            "正常": [c for c in cookie_cards if c["state"] == "正常"],
            "失效": [c for c in cookie_cards if c["state"] == "失效"],
            "未匹配": [c for c in cookie_cards if c["state"] == "未匹配"],
            "未检测": [c for c in cookie_cards if c["state"] == "未检测"],
        }

        # --- 构造解析卡片数据 ---
        parse_cards: List[Dict[str, Any]] = []
        parse_map = {item.get("site_key"): item for item in parse_results if item.get("site_key")}
        for key in sorted(all_site_keys):
            remote = next((s for s in remote_sites if (s.get("key") or s.get("site_key")) == key), {})
            res = parse_map.get(key, {})
            status_text = res.get("status")
            if status_text == "success":
                state = "成功"
                color = "success"
            elif status_text == "partial":
                state = "存疑"
                color = "warning"
            elif status_text == "failed":
                state = "失败"
                color = "error"
            else:
                state = "未检测"
                color = "grey"
            parse_cards.append(
                {
                    "site_name": remote.get("name") or key,
                    "site_key": key,
                    "state": state,
                    "color": color,
                    "username": res.get("username"),
                    "email": res.get("email"),
                    "level": res.get("level"),
                    "register_time": res.get("register_time"),
                    "privacy": res.get("privacy_level"),
                    "reason": res.get("reason", ""),
                    "checked_at": res.get("checked_at", ""),
                }
            )
        parse_grouped = {
            "成功": [p for p in parse_cards if p["state"] == "成功"],
            "存疑": [p for p in parse_cards if p["state"] == "存疑"],
            "失败": [p for p in parse_cards if p["state"] == "失败"],
            "未检测": [p for p in parse_cards if p["state"] == "未检测"],
        }

        # 构造分组卡片（避免前端解析问题，用显式列表）
        cookie_panels: List[Dict[str, Any]] = []
        for group, items in cookie_grouped.items():
            cols = [
                {
                    "component": "VCol",
                    "props": {"cols": 12, "sm": 6, "md": 3, "lg": 3},
                    "content": [
                        {
                            "component": "VCard",
                            "props": {"class": "mb-3", "color": item.get("color"), "variant": "tonal"},
                            "content": [
                                {
                                    "component": "VCardTitle",
                                    "props": {"class": "d-flex justify-space-between align-center"},
                                    "content": [
                                        {"component": "span", "text": item.get("site_name")},
                                        {"component": "VChip", "props": {"color": item.get("color"), "size": "small", "variant": "flat"}, "text": item.get("state")},
                                    ],
                                },
                                {
                                    "component": "VCardText",
                                    "content": [
                                        {"component": "div", "text": f"匹配：{item.get('matched')}"},
                                        {"component": "div", "text": f"有效：{item.get('valid')}"},
                                        {"component": "div", "text": f"原因：{item.get('reason') or '无'}"},
                                        {"component": "div", "text": f"时间：{_fmt_time(item.get('checked_at'))}"},
                                    ],
                                },
                            ],
                        }
                    ],
                }
                for item in items
            ]
            if not cols:
                cols = [{"component": "div", "text": "暂无数据"}]
            cookie_panels.append(
                {
                    "component": "VExpansionPanel",
                    "content": [
                        {"component": "VExpansionPanelTitle", "text": f"{group}（{len(items)}）"},
                        {"component": "VExpansionPanelText", "content": [{"component": "VRow", "content": cols}]},
                    ],
                }
            )

        parse_panels: List[Dict[str, Any]] = []
        for group, items in parse_grouped.items():
            cols = [
                {
                    "component": "VCol",
                    "props": {"cols": 12, "sm": 6, "md": 3, "lg": 3},
                    "content": [
                        {
                            "component": "VCard",
                            "props": {"class": "mb-3", "color": item.get("color"), "variant": "tonal"},
                            "content": [
                                {"component": "VCardTitle", "props": {"class": "d-flex justify-space-between align-center"}, "content": [
                                    {"component": "span", "text": item.get("site_name")},
                                    {"component": "VChip", "props": {"color": item.get("color"), "size": "small", "variant": "flat"}, "text": item.get("state")},
                                ]},
                                {
                                    "component": "VCardText",
                                    "content": [
                                        {"component": "div", "text": f"用户名：{item.get('username') or '-'}"},
                                        {"component": "div", "text": f"邮箱：{item.get('email') or '-'}"},
                                        {"component": "div", "text": f"等级：{item.get('level') or '-'}"},
                                        {"component": "div", "text": f"注册：{item.get('register_time') or '-'}"},
                                        {"component": "div", "text": f"隐私：{item.get('privacy') or '-'}"},
                                        {"component": "div", "text": f"原因：{item.get('reason') or '无'}"},
                                        {"component": "div", "text": f"时间：{_fmt_time(item.get('checked_at'))}"},
                                    ],
                                },
                            ],
                        }
                    ],
                }
                for item in items
            ]
            if not cols:
                cols = [{"component": "div", "text": "暂无数据"}]
            parse_panels.append(
                {
                    "component": "VExpansionPanel",
                    "content": [
                        {"component": "VExpansionPanelTitle", "text": f"{group}（{len(items)}）"},
                        {"component": "VExpansionPanelText", "content": [{"component": "VRow", "content": cols}]},
                    ],
                }
            )

        approve_cnt = int(stats.get("approve", 0))
        reject_cnt = int(stats.get("reject", 0))
        failed_cnt = int(stats.get("failed", 0))
        skipped_cnt = int(stats.get("skipped_no_cookie", 0))
        cookie_valid_cnt = len([c for c in cookie_cards if c["state"] == "正常"])
        cookie_invalid_cnt = len([c for c in cookie_cards if c["state"] == "失效"])
        parse_success_cnt = len([p for p in parse_cards if p["state"] == "成功"])
        parse_fail_cnt = len([p for p in parse_cards if p["state"] == "失败"])
        total_cnt = approve_cnt + reject_cnt + failed_cnt + skipped_cnt or 1
        approve_ratio = int(approve_cnt / total_cnt * 100)
        reject_ratio = int(reject_cnt / total_cnt * 100)
        failed_ratio = int(failed_cnt / total_cnt * 100)
        skipped_ratio = int(skipped_cnt / total_cnt * 100)
        cookie_processed = cookie_valid_cnt + cookie_invalid_cnt
        cookie_ratio = int(cookie_valid_cnt / (cookie_processed or 1) * 100)
        parse_processed = parse_success_cnt + parse_fail_cnt
        parse_ratio = int(parse_success_cnt / (parse_processed or 1) * 100)
        cookie_chart_color = "success" if cookie_processed else "grey"
        parse_chart_color = "info" if parse_processed else "grey"
        cookie_ratio_display = f"{cookie_ratio}%" if cookie_processed else "未检测"
        parse_ratio_display = f"{parse_ratio}%" if parse_processed else "未检测"

        pending_cards = [
            {
                "component": "VCol",
                "props": {"cols": 12, "sm": 6, "md": 3, "lg": 3},
                "content": [
                    {
                        "component": "VCard",
                        "props": {"class": "mb-3", "variant": "tonal"},
                        "content": [
                            {"component": "VCardTitle", "text": f"申请 {item.get('id')}"},
                            {
                                "component": "VCardText",
                                "content": [
                                    {"component": "div", "text": f"类型：{item.get('type')}"},
                                    {"component": "div", "text": f"状态：{item.get('status')} / {item.get('auto_status')}"},
                                    {"component": "div", "text": f"邮箱：{item.get('target_email')}"},
                                    {"component": "div", "text": f"用户名：{item.get('target_username')}"},
                                    {"component": "div", "text": f"创建：{_fmt_time(item.get('created_at'))}"},
                                    {"component": "div", "text": f"更新：{_fmt_time(item.get('updated_at'))}"},
                                ],
                            },
                        ],
                    }
                ],
            }
            for item in pending_apps
        ] or [{"component": "div", "text": "暂无数据"}]

        # 健康统计卡片（固定展示，图形化+更多信息）
        health_card = {
            "component": "VCard",
            "props": {"variant": "tonal", "class": "mb-4"},
            "content": [
                {"component": "VCardTitle", "text": "健康统计"},
                {
                    "component": "VCardText",
                    "content": [
                        {
                            "component": "VRow",
                            "content": [
                                {"component": "VCol", "props": {"cols": 12, "md": 3}, "content": [
                                    {"component": "VSheet", "props": {"class": "pa-3 rounded-lg elevation-1", "color": "success", "variant": "tonal"}, "content": [
                                        {"component": "div", "props": {"class": "text-caption"}, "text": "自动通过"},
                                        {"component": "div", "props": {"class": "text-h5 font-weight-bold"}, "text": approve_cnt},
                                    ]}
                                ]},
                                {"component": "VCol", "props": {"cols": 12, "md": 3}, "content": [
                                    {"component": "VSheet", "props": {"class": "pa-3 rounded-lg elevation-1", "color": "warning", "variant": "tonal"}, "content": [
                                        {"component": "div", "props": {"class": "text-caption"}, "text": "自动拒绝"},
                                        {"component": "div", "props": {"class": "text-h5 font-weight-bold"}, "text": reject_cnt},
                                    ]}
                                ]},
                                {"component": "VCol", "props": {"cols": 12, "md": 3}, "content": [
                                    {"component": "VSheet", "props": {"class": "pa-3 rounded-lg elevation-1", "color": "error", "variant": "tonal"}, "content": [
                                        {"component": "div", "props": {"class": "text-caption"}, "text": "审核失败"},
                                        {"component": "div", "props": {"class": "text-h5 font-weight-bold"}, "text": failed_cnt},
                                    ]}
                                ]},
                                {"component": "VCol", "props": {"cols": 12, "md": 3}, "content": [
                                    {"component": "VSheet", "props": {"class": "pa-3 rounded-lg elevation-1", "color": "info", "variant": "tonal"}, "content": [
                                        {"component": "div", "props": {"class": "text-caption"}, "text": "缺 Cookie 跳过"},
                                        {"component": "div", "props": {"class": "text-h5 font-weight-bold"}, "text": skipped_cnt},
                                    ]}
                                ]},
                            ],
                        },
                        {
                            "component": "VRow",
                            "props": {"class": "mt-2"},
                            "content": [
                                {"component": "VCol", "props": {"cols": 12, "md": 6}, "content": [
                                    {"component": "div", "props": {"class": "mb-1 text-caption text-medium-emphasis"}, "text": "状态占比"},
                                    {"component": "div", "props": {"class": "d-flex flex-wrap gap-6 align-center"}, "content": [
                                        {"component": "div", "props": {"class": "d-flex flex-column align-center", "style": "width: 96px;"}, "content": [
                                            {"component": "VProgressCircular", "props": {"size": 72, "width": 8, "color": "success", "model-value": approve_ratio}, "content": [{"component": "div", "props": {"class": "text-subtitle-2"}, "text": f"{approve_ratio}%"}]},
                                            {"component": "div", "props": {"class": "text-caption mt-1"}, "text": "通过"},
                                        ]},
                                        {"component": "div", "props": {"class": "d-flex flex-column align-center", "style": "width: 96px;"}, "content": [
                                            {"component": "VProgressCircular", "props": {"size": 72, "width": 8, "color": "warning", "model-value": reject_ratio}, "content": [{"component": "div", "props": {"class": "text-subtitle-2"}, "text": f"{reject_ratio}%"}]},
                                            {"component": "div", "props": {"class": "text-caption mt-1"}, "text": "拒绝"},
                                        ]},
                                        {"component": "div", "props": {"class": "d-flex flex-column align-center", "style": "width: 96px;"}, "content": [
                                            {"component": "VProgressCircular", "props": {"size": 72, "width": 8, "color": "error", "model-value": failed_ratio}, "content": [{"component": "div", "props": {"class": "text-subtitle-2"}, "text": f"{failed_ratio}%"}]},
                                            {"component": "div", "props": {"class": "text-caption mt-1"}, "text": "失败"},
                                        ]},
                                        {"component": "div", "props": {"class": "d-flex flex-column align-center", "style": "width: 96px;"}, "content": [
                                            {"component": "VProgressCircular", "props": {"size": 72, "width": 8, "color": "info", "model-value": skipped_ratio}, "content": [{"component": "div", "props": {"class": "text-subtitle-2"}, "text": f"{skipped_ratio}%"}]},
                                            {"component": "div", "props": {"class": "text-caption mt-1"}, "text": "跳过"},
                                        ]},
                                    ]},
                                    {"component": "div", "props": {"class": "d-flex justify-space-between mt-1 text-caption"}, "content": [
                                        {"component": "span", "text": f"通过 {approve_cnt}"},
                                        {"component": "span", "text": f"拒绝 {reject_cnt}"},
                                        {"component": "span", "text": f"失败 {failed_cnt}"},
                                        {"component": "span", "text": f"跳过 {skipped_cnt}"},
                                    ]},
                                ]},
                                {"component": "VCol", "props": {"cols": 12, "md": 6}, "content": [
                                    {"component": "div", "props": {"class": "mb-1 text-caption text-medium-emphasis"}, "text": "配置与时间"},
                                    {"component": "VSheet", "props": {"class": "pa-3 rounded-lg elevation-1", "color": "primary", "variant": "tonal"}, "content": [
                                        {"component": "div", "text": f"API 地址：{config_base_url}"},
                                        {"component": "div", "text": f"站点配置数：{remote_site_count}"},
                                        {"component": "div", "text": f"验证等级：{verification_level}"},
                                        {"component": "div", "props": {"class": "d-flex align-center"}, "content": [
                                            {"component": "span", "text": "在线状态："},
                                            {"component": "VChip", "props": {"size": "small", "color": hb_state_color, "variant": "flat"}, "text": hb_state_text},
                                            {"component": "span", "props": {"class": "text-caption text-medium-emphasis ml-2"}, "text": hb_error or ""},
                                        ]},
                                        {"component": "div", "text": f"最后心跳：{hb_last_heartbeat}"},
                                        {"component": "div", "text": f"最后数据汇报：{hb_last_report}"},
                                        {"component": "div", "text": f"最后配置同步：{last_config_synced}"},
                                        {"component": "div", "text": f"最后审核时间：{last_log_ts}"},
                                    ]},
                                ]},
                            ],
                        },
                        {
                            "component": "VRow",
                            "props": {"class": "mt-2"},
                            "content": [
                                {"component": "VCol", "props": {"cols": 12, "md": 6}, "content": [
                                    {"component": "VSheet", "props": {"class": "pa-3 rounded-lg elevation-1 bg-grey-lighten-4", "variant": "flat"}, "content": [
                                        {"component": "div", "props": {"class": "text-caption text-high-emphasis"}, "text": "Cookie 正常率（已检测）"},
                                        {"component": "VProgressCircular", "props": {"size": 72, "width": 8, "color": cookie_chart_color, "model-value": cookie_ratio}, "content": [
                                            {"component": "div", "props": {"class": "text-subtitle-2"}, "text": cookie_ratio_display},
                                        ]},
                                        {"component": "div", "props": {"class": "text-caption text-medium-emphasis mt-1"}, "text": f"正常 {cookie_valid_cnt} / 失效 {cookie_invalid_cnt} / 已检测 {cookie_processed} / 总 {len(cookie_cards)}"},
                                        {"component": "div", "props": {"class": "text-caption text-medium-emphasis"}, "text": "比例按已检测（正常+失效）计算，未检测未参与比例"},
                                    ]},
                                ]},
                                {"component": "VCol", "props": {"cols": 12, "md": 6}, "content": [
                                    {"component": "VSheet", "props": {"class": "pa-3 rounded-lg elevation-1 bg-grey-lighten-4", "variant": "flat"}, "content": [
                                        {"component": "div", "props": {"class": "text-caption text-high-emphasis"}, "text": "解析成功率（已检测）"},
                                        {"component": "VProgressCircular", "props": {"size": 72, "width": 8, "color": parse_chart_color, "model-value": parse_ratio}, "content": [
                                            {"component": "div", "props": {"class": "text-subtitle-2"}, "text": parse_ratio_display},
                                        ]},
                                        {"component": "div", "props": {"class": "text-caption text-medium-emphasis mt-1"}, "text": f"成功 {parse_success_cnt} / 失败 {parse_fail_cnt} / 已检测 {parse_processed} / 总 {len(parse_cards)}"},
                                        {"component": "div", "props": {"class": "text-caption text-medium-emphasis"}, "text": "比例按已检测（成功+失败）计算，未检测未参与比例"},
                                    ]},
                                ]},
                            ],
                        },
                    ],
                },
            ],
        }

        accordion = {
            "component": "VExpansionPanels",
            "props": {"multiple": False, "variant": "accordion", "model": "luckpt_panels_secondary", "modelValue": ["日志"]},
            "content": [
                {
                    "component": "VExpansionPanel",
                    "props": {"value": "日志"},
                    "content": [
                        {"component": "VExpansionPanelTitle", "text": "审核日志"},
                        {"component": "VExpansionPanelText", "content": [
                            {"component": "VTimeline", "props": {"truncate-line": "both", "density": "compact"}, "content": log_timeline_items},
                        ]},
                    ],
                },
                {
                    "component": "VExpansionPanel",
                    "props": {"value": "待审核"},
                    "content": [
                        {"component": "VExpansionPanelTitle", "text": "待审核列表"},
                        {"component": "VExpansionPanelText", "content": [
                            {"component": "VRow", "content": pending_cards},
                        ]},
                    ],
                },
                {
                    "component": "VExpansionPanel",
                    "props": {"value": "Cookie"},
                    "content": [
                        {"component": "VExpansionPanelTitle", "text": "Cookie 匹配与有效性"},
                        {"component": "VExpansionPanelText", "content": [
                            {"component": "VExpansionPanels", "props": {"variant": "accordion", "multiple": True}, "content": cookie_panels}
                        ]},
                    ],
                },
                {
                    "component": "VExpansionPanel",
                    "props": {"value": "解析"},
                    "content": [
                        {"component": "VExpansionPanelTitle", "text": "解析检测结果"},
                        {"component": "VExpansionPanelText", "content": [
                            {"component": "VExpansionPanels", "props": {"variant": "accordion", "multiple": True}, "content": parse_panels}
                        ]},
                    ],
                },
            ],
        }

        return [health_card, accordion]

    def _fetch_applications(self, auto_status: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        仅用于页面展示时拉取数据。
        """
        if not self.config_mgr or not self.config_mgr.api_token:
            return []
        query = {"page": 1, "per_page": 50}
        if auto_status:
            query["auto_status"] = auto_status
            logger.debug("页面拉取申请列表，auto_status=%s", auto_status)
        url = self.config_mgr.api_base.rstrip("/") + "/api/v1/site-verifications"
        headers = {"Authorization": f"Bearer {self.config_mgr.api_token}", "Content-Type": "application/json"}
        proxies = self.config_mgr.api_proxies
        for attempt in range(3):
            try:
                res = RequestUtils(headers=headers, timeout=15, proxies=proxies).get_res(url, params=query)
                if res and res.status_code == 200:
                    payload = res.json()
                    if str(payload.get("ret")) == "0":
                        data_list = payload.get("data", {}).get("data") or []
                        if attempt > 0:
                            logger.info("页面申请列表重试成功，第%s次", attempt + 1)
                        logger.debug("页面拉取申请列表成功，数量=%s", len(data_list))
                        return data_list
                    logger.warning("页面申请列表响应 ret!=0 #%s：%s", attempt + 1, payload.get("msg"))
                else:
                    logger.warning("页面申请列表 HTTP 失败 #%s：%s", attempt + 1, res.status_code if res else "无响应")
            except Exception as exc:
                logger.warning("页面申请列表请求异常 #%s：%s", attempt + 1, exc)
            if attempt < 2:
                time.sleep(1)
        return []

    # -------------- 命令 / API --------------
    def get_command(self) -> List[Dict[str, Any]]:
        return []

    def get_api(self) -> List[Dict[str, Any]]:
        return []

    def get_service(self) -> List[Dict[str, Any]]:
        return []


plugin_class = LuckPTAutoReview
