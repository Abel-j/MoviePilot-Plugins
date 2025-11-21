import random
import json
import time
import re
from datetime import datetime, timedelta
from typing import Any, List, Dict, Tuple, Optional

import pytz # 确保导入 pytz
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from app.core.config import settings
from app.core.event import eventmanager
from app.helper.cookie import CookieHelper
from app.log import logger
from app.plugins import _PluginBase
from app.utils.http import RequestUtils
from app.utils.string import StringUtils
from app.schemas import NotificationType
from app.helper.sites import SitesHelper
from urllib.parse import urlparse
import traceback
from bs4 import BeautifulSoup # 确保导入


class LuckPTAutoReview(_PluginBase):
    # 插件名称
    plugin_name = "蜂巢邀请监控"
    # 插件描述
    plugin_desc = "蜂巢论坛管理组定制专用"
    # 插件图标
    plugin_icon = "https://pt.luckpt.de/logo1.png"
    # 插件版本
    plugin_version = "1.1.4"
    # 插件作者
    plugin_author = "miss"
    # 作者主页
    author_url = "https://pt.luckpt.de/"
    # 插件配置项ID前缀
    plugin_config_prefix = "luckptautoreview_"
    # 加载顺序
    plugin_order = 31
    # 可使用的用户级别
    auth_level = 2

    # 私有属性
    _enabled = False
    _notify = False
    _cron = None
    _onlyonce = False
    _proxy = None
    _username = None
    _password = None
    _check_interval = None
    _pending_reviews = None
    _retry_count = None
    _retry_interval = None
    _use_proxy = True
    _auto_approve_enabled = False # 新增类属性
    
    # 定时器
    _scheduler: Optional[BackgroundScheduler] = None
    sites: Optional[SitesHelper] = None

    # 定义不通过等级列表 (移到类级别或合适位置)
    not_pass_levels = [
        'Peasant', 'User', '无名小辈', '伯曼猫 USER', 
        '(士兵)User', '(小鬼当家)User', '新人', '初级训练家(User)', 
        '未找到等级信息', '无法访问/提取', '未提取到等级' # 加入提取失败的情况
    ]

    def init_plugin(self, config: dict = None):
        self.sites = SitesHelper()
        self.stop_service()

        if config:
            self._enabled = config.get("enabled", False)
            self._notify = config.get("notify", True)
            self._cron = config.get("cron")
            self._onlyonce = config.get("onlyonce", False)
            self._username = config.get("username")
            self._password = config.get("password")
            self._check_interval = config.get("check_interval", 5)
            self._retry_count = int(config.get("retry_count", 3)) # 确保是整数
            self._retry_interval = int(config.get("retry_interval", 5)) # 确保是整数
            self._use_proxy = config.get("use_proxy", True)
            self._auto_approve_enabled = config.get("auto_approve_enabled", False) # 读取新配置
            self._pending_reviews = self.get_data('pending_reviews') or {}

        # 启动服务
        if self._enabled:
            # 创建独立的 scheduler 实例
            self._scheduler = BackgroundScheduler(timezone=settings.TZ)
            
            if self._onlyonce:
                logger.info(f"监控蜂巢论坛邀请 (一次性任务注册)...")
                # 立即执行一次检查，使用 run_date
                self._scheduler.add_job(func=self.check_invites, trigger='date',
                                   run_date=datetime.now(tz=pytz.timezone(settings.TZ)) + timedelta(seconds=3),
                                   id=f"{self.__class__.__name__}_check_invite_once",
                                   name=f"蜂巢邀请监控服务 (一次性)")
                # 关闭一次性开关
                self._onlyonce = False
                # 添加 update_config 调用以保存 onlyonce 的状态
                self.update_config({
                    "enabled": self._enabled,
                    "notify": self._notify,
                    "cron": self._cron,
                    "onlyonce": self._onlyonce, # <<< 确保保存为 False
                    "username": self._username,
                    "password": self._password,
                    "check_interval": self._check_interval,
                    "retry_count": self._retry_count,
                    "retry_interval": self._retry_interval,
                    "use_proxy": self._use_proxy,
                    "auto_approve_enabled": self._auto_approve_enabled # 保存新配置
                    # pending_reviews 是运行时数据，不应在此保存
                })
            
            # 添加周期性任务
            if self._cron:
                logger.info(f"监控蜂巢论坛邀请服务启动，定时任务：{self._cron}")
                try:
                    # 使用 CronTrigger.from_crontab
                    self._scheduler.add_job(func=self.check_invites,
                                            trigger=CronTrigger.from_crontab(self._cron),
                                            id=f"{self.__class__.__name__}_check_invite_cron",
                                            name=f"蜂巢邀请监控服务 (Cron)")
                except Exception as e:
                    logger.error(f"添加 Cron 任务失败: {str(e)}")
            # 添加间隔任务（仅当没有 cron 时）
            elif self._check_interval and int(self._check_interval) > 0: 
                logger.info(f"监控蜂巢论坛邀请服务启动，间隔：{self._check_interval}分钟")
                try:
                    self._scheduler.add_job(func=self.check_invites,
                                            trigger="interval",
                                            minutes=int(self._check_interval),
                                            id=f"{self.__class__.__name__}_check_invite_interval",
                                            name=f"蜂巢邀请监控服务 (间隔)")
                except Exception as e:
                    logger.error(f"添加 Interval 任务失败: {str(e)}")
            
            # 启动 scheduler (如果添加了任务)
            if self._scheduler and self._scheduler.get_jobs():
                try:
                    self._scheduler.start()
                    logger.info(f"蜂巢邀请监控服务的 Scheduler 已启动")
                except Exception as e:
                    logger.error(f"启动 Scheduler 失败: {str(e)}")
                    self._scheduler = None # 启动失败则重置
        else:
            logger.info("蜂巢邀请监控插件未启用")
            
    def get_state(self) -> bool:
        """
        获取插件状态
        """
        return self._enabled
    
    @staticmethod
    def get_command() -> List[Dict[str, Any]]:
        """
        注册命令
        """
        return []

    def get_api(self) -> List[Dict[str, Any]]:
        """
        注册API
        """
        return []

    def get_service(self) -> List[Dict[str, Any]]:
        """
        注册服务 (如果需要对外提供)
        """
        return [] 
    
    def get_form(self) -> Tuple[List[dict], Dict[str, Any]]:
        """
        拼装插件配置页面，需要返回两块数据：1、页面配置；2、数据结构
        """
        return [
            {
                'component': 'VForm',
                'content': [
                    {
                        'component': 'VRow',
                        'content': [
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 4
                                },
                                'content': [
                                    {
                                        'component': 'VSwitch',
                                        'props': {
                                            'model': 'enabled',
                                            'label': '启用插件',
                                        }
                                    }
                                ]
                            },
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 4
                                },
                                'content': [
                                    {
                                        'component': 'VSwitch',
                                        'props': {
                                            'model': 'notify',
                                            'label': '开启通知',
                                        }
                                    }
                                ]
                            },
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 4
                                },
                                'content': [
                                    {
                                        'component': 'VSwitch',
                                        'props': {
                                            'model': 'onlyonce',
                                            'label': '立即运行一次',
                                        }
                                    }
                                ]
                            }
                        ]
                    },
                    # 用户名密码输入
                    {
                        'component': 'VRow',
                        'content': [
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 6
                                },
                                'content': [
                                    {
                                        'component': 'VTextField',
                                        'props': {
                                            'model': 'username',
                                            'label': '用户名',
                                            'placeholder': '蜂巢论坛用户名',
                                            'hint': '请输入蜂巢论坛用户名'
                                        }
                                    }
                                ]
                            },
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 6
                                },
                                'content': [
                                    {
                                        'component': 'VTextField',
                                        'props': {
                                            'model': 'password',
                                            'label': '密码',
                                            'placeholder': '蜂巢论坛密码',
                                            'type': 'password',
                                            'hint': '请输入蜂巢论坛密码'
                                        }
                                    }
                                ]
                            }
                        ]
                    },
                    # 监控周期和重试设置
                    {
                        'component': 'VRow',
                        'content': [
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 6
                                },
                                'content': [
                                    {
                                        'component': 'VCronField',
                                        'props': {
                                            'model': 'cron',
                                            'label': '定时周期',
                                            'placeholder': '*/5 * * * *',
                                            'hint': '填写cron表达式，留空则使用固定间隔'
                                        }
                                    }
                                ]
                            },
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 6
                                },
                                'content': [
                                    {
                                        'component': 'VTextField',
                                        'props': {
                                            'model': 'check_interval',
                                            'label': '固定间隔(分钟)',
                                            'placeholder': '5',
                                            'hint': '未配置cron表达式时使用，每隔多少分钟检查一次'
                                        }
                                    }
                                ]
                            }
                        ]
                    },
                    # 失败重试设置
                    {
                        'component': 'VRow',
                        'content': [
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 6
                                },
                                'content': [
                                    {
                                        'component': 'VTextField',
                                        'props': {
                                            'model': 'retry_count',
                                            'label': '失败重试次数',
                                            'type': 'number',
                                            'placeholder': '3',
                                            'hint': '请求失败重试次数'
                                        }
                                    }
                                ]
                            },
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 6
                                },
                                'content': [
                                    {
                                        'component': 'VTextField',
                                        'props': {
                                            'model': 'retry_interval',
                                            'label': '重试间隔(秒)',
                                            'type': 'number',
                                            'placeholder': '5',
                                            'hint': '请求失败多少秒后重试'
                                        }
                                    }
                                ]
                            }
                        ]
                    },
                    # 代理设置
                    {
                        'component': 'VRow',
                        'content': [
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 6
                                },
                                'content': [
                                    {
                                        'component': 'VSwitch',
                                        'props': {
                                            'model': 'use_proxy',
                                            'label': '使用代理',
                                            'hint': '与蜂巢论坛通信时使用系统代理'
                                        }
                                    }
                                ]
                            }
                        ]
                    },
                    # --- 新增：自动审核开关 ---
                    {
                        'component': 'VRow',
                        'content': [
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 6
                                },
                                'content': [
                                    {
                                        'component': 'VSwitch',
                                        'props': {
                                            'model': 'auto_approve_enabled',
                                            'label': '启用自动审核通过',
                                            'hint': '当内部验证通过且等级不是VIP时，自动调用API通过审核'
                                        }
                                    }
                                ]
                            }
                        ]
                    },
                    # --- 新增结束 ---
                    # 提示
                    {
                        'component': 'VRow',
                        'content': [
                            {
                                'component': 'VCol',
                                'props': {'cols': 12},
                                'content': [
                                    {
                                        'component': 'VAlert',
                                        'props': {
                                            'type': 'info',
                                            'variant': 'tonal',
                                            'text': '此插件用于监控蜂巢论坛的邀请审核状态，当有新的待审核邀请或邀请长时间未审核时，将通过MoviePilot通知系统推送信息。'
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        ], {
            "enabled": False,
            "notify": True,
            "cron": "*/5 * * * *",
            "onlyonce": False,
            "username": "",
            "password": "",
            "check_interval": 5,
            "retry_count": 3,
            "retry_interval": 5,
            "use_proxy": True,
            "auto_approve_enabled": False # 新增默认值
        }

    def get_page(self) -> List[dict]:
        """
        构建插件详情页面，展示待审核邀请的详细信息及初步判断
        """
        invite_details = self.get_data('pending_invites_details') or {}
        
        if not invite_details:
            return [
                {
                    'component': 'VAlert',
                    'props': {
                        'type': 'info',
                        'variant': 'tonal',
                        'text': '当前没有待审核的邀请记录。',
                        'class': 'mb-2',
                        'prepend-icon': 'mdi-information-outline'
                    }
                }
            ]
        
        invite_list = []
        for item_id, details in invite_details.items():
            details['id'] = item_id
            invite_list.append(details)
            
        try:
             invite_list.sort(key=lambda x: x.get('timestamp', '0'), reverse=True)
        except Exception as e:
            logger.error(f"邀请列表排序失败: {e}")

        invite_cards = []
        for invite in invite_list:
            item_id = invite.get('id', 'N/A')
            timestamp_str = invite.get('timestamp', '')
            # --- 从存储的数据中获取信息 --- 
            inviter = invite.get('inviter', '未知') # 邀请人
            invitee_email_api = invite.get('invitee_email_api', '未知')
            invitee_username_api = invite.get('invitee_username_api', '未知')
            link1 = invite.get('link1', '')
            link2 = invite.get('link2', '')
            is_main_account = invite.get('is_main_account', False)
            link1_extracted_username = invite.get('link1_extracted_username')
            link1_extracted_email = invite.get('link1_extracted_email')
            link1_extracted_level = invite.get('link1_extracted_level')
            link1_status = invite.get('link1_status', {})
            link2_extracted_username = invite.get('link2_extracted_username')
            link2_extracted_email = invite.get('link2_extracted_email')
            link2_extracted_level = invite.get('link2_extracted_level')
            link2_status = invite.get('link2_status', {})
            final_pass = invite.get('final_pass_status', False) # 获取最终判断结果
            
            # --- 根据最终判断结果确定状态和颜色 ---
            judgment_status = "通过" if final_pass else "不通过"
            status_color = "success" if final_pass else "error"
            
            # --- 构建判断原因 --- 
            reasons = []
            if link1:
                l1_reason = "链接1: "
                if link1_status.get('error'):
                    l1_reason += f"验证失败 ({link1_status['error']})"
                elif link1_status.get('verified'):
                    l1_reason += "✅ 通过"
                else:
                    l1_fail_reasons = []
                    if not link1_status.get('username_match'): l1_fail_reasons.append("用户名不匹配")
                    if not link1_status.get('email_match'): l1_fail_reasons.append("邮箱不匹配")
                    if not link1_status.get('level_ok'): l1_fail_reasons.append("等级不符")
                    l1_reason += f"❌ 不通过 ({ ', '.join(l1_fail_reasons) if l1_fail_reasons else '未知原因' })"
                reasons.append(l1_reason)
            if link2:
                l2_reason = "链接2: "
                if link2_status.get('error'):
                    l2_reason += f"验证失败 ({link2_status['error']})"
                elif link2_status.get('verified'):
                    l2_reason += "✅ 通过"
                else:
                    l2_fail_reasons = []
                    if not link2_status.get('username_match'): l2_fail_reasons.append("用户名不匹配")
                    if not link2_status.get('email_match'): l2_fail_reasons.append("邮箱不匹配")
                    if not link2_status.get('level_ok'): l2_fail_reasons.append("等级不符")
                    l2_reason += f"❌ 不通过 ({ ', '.join(l2_fail_reasons) if l2_fail_reasons else '未知原因' })"
                reasons.append(l2_reason)
            
            if not link1 and not link2:
                 reasons.append("未提供验证链接")
                 status_color = "grey"
                 judgment_status = "无法验证"
                 
            judgment_reason = " | ".join(reasons)
             
            # --- 格式化时间戳和计算持续时间 (代码不变) --- 
            display_time = timestamp_str
            duration_str = "未知"
            duration_color = "grey"
            duration_icon = "mdi-help-circle"
            if timestamp_str:
                try:
                    dt_obj = datetime.fromisoformat(timestamp_str)
                    display_time = dt_obj.strftime('%Y-%m-%d %H:%M:%S')
                    duration = datetime.now(dt_obj.tzinfo) - dt_obj
                    days, remainder = divmod(duration.total_seconds(), 86400)
                    hours, remainder = divmod(remainder, 3600)
                    minutes, seconds = divmod(remainder, 60)
                    duration_str = f"{int(days)}天 {int(hours)}小时 {int(minutes)}分"
                    # 根据等待时间调整颜色，但优先使用判断结果的颜色
                    base_duration_color = "error" if duration.total_seconds() > 4 * 3600 else "warning" if duration.total_seconds() > 2 * 3600 else "info"
                    base_duration_icon = "mdi-alert-circle" if base_duration_color == "error" else "mdi-clock-alert-outline" if base_duration_color == "warning" else "mdi-timer-sand"
                except ValueError:
                    display_time = "时间格式错误"
            else:
                display_time = "无时间记录"

            invite_cards.append({
                'component': 'VCard',
                'props': {'class': 'mb-3 elevation-1', 'variant': 'outlined'},
                'content': [
                    {
                        'component': 'VCardTitle',
                        'props': {'class': 'd-flex align-center py-2', 'style': f'background-color: rgba(var(--v-theme-{status_color}), 0.1); border-bottom: 1px solid rgba(0,0,0,0.1);'},
                        'content': [
                            {
                                'component': 'VIcon',
                                'props': {'color': status_color, 'class': 'mr-2'},
                                'text': 'mdi-email-fast-outline'
                            },
                            {
                                'component': 'span',
                                'props': {'class': 'text-body-1 font-weight-medium'},
                                'text': f'待审核邀请 (ID: {item_id})'
                            },
                            # --- 新增：主账号标识 --- 
                            {
                                'component': 'VChip',
                                'props': {
                                    'color': 'primary', # 主账号用醒目颜色
                                    'size': 'x-small',
                                    'class': 'ml-2',
                                    'variant': 'flat',
                                    'prepend-icon': 'mdi-account-check'
                                },
                                'text': '主账号邀请'
                            } if is_main_account else {},
                            # --- 新增结束 ---
                            {
                                'component': 'VSpacer'
                            },
                            # --- 修改: 显示最终判断状态 Chip --- 
                            {
                                'component': 'VChip',
                                'props': {
                                    'color': status_color,
                                    'size': 'small',
                                    'variant': 'flat', # 实心更好看
                                    'prepend-icon': 'mdi-check-decagram' if status_color == 'success' else 'mdi-alert-decagram' if status_color == 'error' else 'mdi-help-circle-outline'
                                },
                                'text': judgment_status # 直接显示判断状态
                            }
                        ]
                    },
                    {
                        'component': 'VCardText',
                        'props': {'class': 'pa-3'},
                        'content': [
                            # --- 添加: 判断依据 --- 
                            {
                                'component': 'div',
                                'props': {'class': f'd-flex align-start mb-2 pa-2 rounded text-caption text-{status_color}', 'style': f'background-color: rgba(var(--v-theme-{status_color}), 0.05); border: 1px solid rgba(var(--v-theme-{status_color}), 0.2);'},
                                'content': [
                                    {
                                        'component': 'VIcon',
                                        'props': {'size': 'small', 'class': 'mr-2', 'style': f'color: {status_color}; margin-top: 1px;'},
                                        'text': 'mdi-information-outline'
                                    },
                                    {
                                        'component': 'span',
                                        'text': judgment_reason
                                    }
                                ]
                            },
                            # 邀请人
                            {
                                'component': 'div',
                                'props': {'class': 'd-flex align-center mb-2'},
                                'content': [
                                    {'component': 'VIcon', 'props': {'size': 'small', 'color': 'blue-grey-darken-1', 'class': 'mr-2'}, 'text': 'mdi-account-arrow-right'},
                                    {'component': 'span', 'props': {'class': 'font-weight-bold mr-2', 'style': 'min-width: 100px;'}, 'text': '邀请人:'},
                                    {'component': 'span', 'text': inviter}
                                ]
                            },
                            # 受邀人用户名 (来自 API)
                            {
                                'component': 'div',
                                'props': {'class': 'd-flex align-center mb-2'},
                                'content': [
                                    {'component': 'VIcon', 'props': {'size': 'small', 'color': 'blue-grey-darken-1', 'class': 'mr-2'}, 'text': 'mdi-account'},
                                    {'component': 'span', 'props': {'class': 'font-weight-bold mr-2', 'style': 'min-width: 100px;'}, 'text': '受邀人用户名(API):'},
                                    {'component': 'span', 'text': invitee_username_api}
                                ]
                            },
                            # 受邀人邮箱 (来自 API)
                            {
                                'component': 'div',
                                'props': {'class': 'd-flex align-center mb-2'},
                                'content': [
                                    {'component': 'VIcon', 'props': {'size': 'small', 'color': 'blue-grey-darken-1', 'class': 'mr-2'}, 'text': 'mdi-email'},
                                    {'component': 'span', 'props': {'class': 'font-weight-bold mr-2', 'style': 'min-width: 100px;'}, 'text': '受邀人邮箱(API):'},
                                    {'component': 'span', 'text': invitee_email_api}
                                ]
                            },
                            # --- 链接1 验证详情 --- 
                            {
                                'component': 'VExpansionPanels',
                                'props': {'variant': 'accordion', 'class': 'mt-2 mb-1', 'style': 'font-size: 0.8rem;'},
                                'content': [
                                    {
                                        'component': 'VExpansionPanel',
                                        'content': [
                                            {
                                                'component': 'VExpansionPanelTitle',
                                                'props': {'class': 'pa-2', 'style': 'min-height: 36px;'},
                                                'content': [
                                                    {
                                                        'component': 'div',
                                                        'props': {'class': 'd-flex align-center w-100'},
                                                        'content': [
                                                            {'component': 'VIcon', 'props': {'size': 'small', 'class': 'mr-1', 'color': 'link1_verified' if link1_status.get('verified') else ('error' if link1_status.get('error') else 'grey')}, 'text': 'mdi-link-variant'},
                                                            {'component': 'span', 'props': {'class': 'text-caption font-weight-medium'}, 'text': '链接1验证'},
                                                            {'component': 'VSpacer'},
                                                            {'component': 'VChip', 'props': {'size': 'x-small', 'color': 'success' if link1_status.get('verified') else ('error' if not link1_status.get('error') else 'grey'), 'variant': 'flat'}, 'text': '通过' if link1_status.get('verified') else ('失败' if link1_status.get('error') else '不通过')}
                                                        ]
                                                    }
                                                ]
                                            },
                                            {
                                                'component': 'VExpansionPanelText',
                                                'props': {'class': 'pa-2 text-caption'},
                                                'content': [
                                                    # 使用 VBtn 或 a 标签使链接可点击
                                                    {
                                                        'component': 'div', 
                                                        'content': [
                                                            {'component': 'span', 'text': '链接: ', 'props': {'class': 'mr-1'}},
                                                            {
                                                                'component': 'a', 
                                                                'props': {'href': link1, 'target': '_blank', 'style': 'word-break: break-all;'}, 
                                                                'text': link1 or '无'
                                                            }
                                                        ]
                                                    } if link1 else {'component': 'div', 'text': '链接: 无'},
                                                    {'component': 'div', 'text': f"验证状态: {link1_status.get('error') or ('通过' if link1_status.get('verified') else '不通过')}"},
                                                    {'component': 'div', 'text': f"提取用户: {link1_extracted_username or 'N/A'} ({ '✅匹配' if link1_status.get('username_match') else '❌不符' })"},
                                                    {'component': 'div', 'text': f"提取邮箱: {link1_extracted_email or 'N/A'} ({ '✅匹配' if link1_status.get('email_match') else '❌不符' })"},
                                                    {'component': 'div', 'text': f"提取等级: {link1_extracted_level or 'N/A'} ({ '✅通过' if link1_status.get('level_ok') else '❌不符' })"}
                                                ]
                                            }
                                        ]
                                    } if link1 else {},
                                    {
                                        'component': 'VExpansionPanel',
                                        'content': [
                                            {
                                                'component': 'VExpansionPanelTitle',
                                                'props': {'class': 'pa-2', 'style': 'min-height: 36px;'},
                                                'content': [
                                                    {
                                                        'component': 'div',
                                                        'props': {'class': 'd-flex align-center w-100'},
                                                        'content': [
                                                            {'component': 'VIcon', 'props': {'size': 'small', 'class': 'mr-1', 'color': 'link2_verified' if link2_status.get('verified') else ('error' if link2_status.get('error') else 'grey')}, 'text': 'mdi-link-variant'},
                                                            {'component': 'span', 'props': {'class': 'text-caption font-weight-medium'}, 'text': '链接2验证'},
                                                            {'component': 'VSpacer'},
                                                            {'component': 'VChip', 'props': {'size': 'x-small', 'color': 'success' if link2_status.get('verified') else ('error' if not link2_status.get('error') else 'grey'), 'variant': 'flat'}, 'text': '通过' if link2_status.get('verified') else ('失败' if link2_status.get('error') else '不通过')}
                                                        ]
                                                    }
                                                ]
                                            },
                                            {
                                                'component': 'VExpansionPanelText',
                                                'props': {'class': 'pa-2 text-caption'},
                                                'content': [
                                                    # 使用 VBtn 或 a 标签使链接可点击
                                                    {
                                                        'component': 'div', 
                                                        'content': [
                                                            {'component': 'span', 'text': '链接: ', 'props': {'class': 'mr-1'}},
                                                            {
                                                                'component': 'a', 
                                                                'props': {'href': link2, 'target': '_blank', 'style': 'word-break: break-all;'}, 
                                                                'text': link2 or '无'
                                                            }
                                                        ]
                                                    } if link2 else {'component': 'div', 'text': '链接: 无'},
                                                    {'component': 'div', 'text': f"验证状态: {link2_status.get('error') or ('通过' if link2_status.get('verified') else '不通过')}"},
                                                    {'component': 'div', 'text': f"提取用户: {link2_extracted_username or 'N/A'} ({ '✅匹配' if link2_status.get('username_match') else '❌不符' })"},
                                                    {'component': 'div', 'text': f"提取邮箱: {link2_extracted_email or 'N/A'} ({ '✅匹配' if link2_status.get('email_match') else '❌不符' })"},
                                                    {'component': 'div', 'text': f"提取等级: {link2_extracted_level or 'N/A'} ({ '✅通过' if link2_status.get('level_ok') else '❌不符' })"}
                                                ]
                                            }
                                        ]
                                    } if link2 else {}
                                ]
                            },
                            # 记录时间和等待时长
                            {
                                'component': 'div',
                                'props': {'class': 'd-flex align-center mt-2 text-caption text-grey-darken-1'},
                                'content': [
                                    {
                                        'component': 'div',
                                        'props': {'class': 'mr-4 d-flex align-center'},
                                        'content': [
                                             {'component': 'VIcon', 'props': {'size': 'x-small', 'class': 'mr-1'}, 'text': 'mdi-clock-outline'},
                                             {'component': 'span', 'text': f'记录: {display_time}'}
                                        ]
                                    },
                                    {
                                        'component': 'div',
                                        'props': {'class': 'd-flex align-center'},
                                        'content': [
                                             {'component': 'VIcon', 'props': {'size': 'x-small', 'class': 'mr-1', 'color': base_duration_color}, 'text': base_duration_icon},
                                             {'component': 'span', 'text': f'已等: {duration_str}'}
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                ]
            })

        # 最终页面结构 (与之前相同)
        return [
            {
                'component': 'div',
                'props': {'class': 'd-flex align-center mb-3'},
                'content': [
                    {'component': 'VIcon', 'props': {'size': 'large', 'color': 'primary', 'class': 'mr-2'}, 'text': 'mdi-account-multiple-check'},
                    {
                        'component': 'div',
                        'content': [
                            {'component': 'div', 'props': {'class': 'text-h6 font-weight-medium'}, 'text': '蜂巢待审核邀请列表'},
                            {'component': 'div', 'props': {'class': 'text-body-2 text-grey-darken-1'}, 'text': f'当前共有 {len(invite_list)} 条待审核邀请记录'}
                        ]
                    }
                ]
            },
            *invite_cards
        ]

    def stop_service(self):
        """
        停止服务并清理 scheduler
        """
        try:
            if self._scheduler:
                if self._scheduler.running:
                    self._scheduler.remove_all_jobs()
                    self._scheduler.shutdown()
                    logger.info("蜂巢邀请监控服务的 Scheduler 已关闭")
                self._scheduler = None
        except Exception as e:
            logger.error(f"停止服务失败: {str(e)}")

    def check_invites(self):
        """
        检查待审核邀请
        """
        if not self._enabled:
            return
        
        logger.info(f"开始检查蜂巢论坛待审核邀请...")

        if not self._username or not self._password:
            logger.error("用户名或密码未配置，无法检查待审核邀请")
            self.send_msg("蜂巢邀请监控", "用户名或密码未配置，无法检查待审核邀请")
            return

        # 登录获取Cookie
        proxies = self._get_proxies()
        cookie = self._login_and_get_cookie(proxies)
        if not cookie:
            # 只记录日志，不发送通知，避免因网络问题频繁推送通知
            logger.error("登录失败，无法获取Cookie")
            return

        # 检查待审核邀请
        self._check_invites_with_cookie(cookie)

    def _get_proxies(self):
        """
        获取代理设置
        """
        if not self._use_proxy:
            logger.info("未启用代理")
            return None
            
        try:
            if hasattr(settings, 'PROXY') and settings.PROXY:
                logger.info(f"使用系统代理: {settings.PROXY}")
                return settings.PROXY
            else:
                logger.warning("系统代理未配置")
                return None
        except Exception as e:
            logger.error(f"获取代理设置出错: {str(e)}")
            return None

    def _login_and_get_cookie(self, proxies=None):
        """
        使用用户名密码登录获取cookie (参考 fengchaosignin)
        """
        try:
            logger.info(f"开始使用用户名'{self._username}'登录蜂巢论坛(邀请插件)...")
            req = RequestUtils(proxies=proxies, timeout=30)
            proxy_info = "代理" if proxies else "直接连接"
            
            # --- 第一步：GET请求获取CSRF和初始cookie --- 
            logger.info(f"步骤1: GET请求获取CSRF和初始cookie (使用{proxy_info})...")
            get_headers = {
                "Accept": "*/*",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
                "Cache-Control": "no-cache"
            }
            try:
                res = req.get_res("https://pting.club", headers=get_headers)
                if not res or res.status_code != 200:
                    logger.error(f"GET请求失败，状态码: {res.status_code if res else '无响应'} (使用{proxy_info})")
                    return None
            except Exception as e:
                logger.error(f"GET请求异常 (使用{proxy_info}): {str(e)}")
                return None
                
            # 获取CSRF令牌 (优先从Header，其次HTML)
            csrf_token = res.headers.get('x-csrf-token')
            if not csrf_token:
                pattern = r'"csrfToken":"(.*?)"'
                csrf_matches = re.findall(pattern, res.text)
                if csrf_matches:
                    csrf_token = csrf_matches[0]
                else:
                    logger.error(f"无法获取CSRF令牌 (使用{proxy_info})")
                    return None
            logger.info(f"获取到CSRF令牌: {csrf_token}")
            
            # 获取初始session cookie
            session_cookie = None
            initial_cookies = res.cookies.get_dict()
            session_cookie = initial_cookies.get('flarum_session')
            if not session_cookie:
                 # 尝试从 set-cookie Header 获取
                 set_cookie_header = res.headers.get('set-cookie')
                 if set_cookie_header:
                     session_match = re.search(r'flarum_session=([^;]+)', set_cookie_header)
                     if session_match:
                         session_cookie = session_match.group(1)
            
            if not session_cookie:
                logger.error(f"无法获取初始session cookie (使用{proxy_info})")
                return None
            logger.info(f"获取到初始session cookie: {session_cookie[:10]}...")
                
            # --- 第二步：POST请求登录 --- 
            logger.info(f"步骤2: POST请求登录 (使用{proxy_info})...")
            login_data = {
                "identification": self._username,
                "password": self._password,
                "remember": True
            }
            login_headers = {
                "Content-Type": "application/json",
                "X-CSRF-Token": csrf_token,
                "Cookie": f"flarum_session={session_cookie}", # 带上初始session cookie
                "Accept": "*/*",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
                "Cache-Control": "no-cache"
            }
            logger.info(f"登录数据: {{'identification': '{self._username}', 'password': '******', 'remember': True}}")
            
            try:
                login_res = req.post_res(
                    url="https://pting.club/login",
                    json=login_data,
                    headers=login_headers
                )
                if not login_res:
                    logger.error(f"登录请求失败，未收到响应 (使用{proxy_info})")
                    return None
                logger.info(f"登录请求返回状态码: {login_res.status_code}")
                if login_res.status_code != 200:
                    logger.error(f"登录请求失败，状态码: {login_res.status_code} (使用{proxy_info})")
                    try:
                        error_content = login_res.text[:300] if login_res.text else "无响应内容"
                        logger.error(f"登录错误响应: {error_content}")
                    except:
                        pass
                    return None
            except Exception as e:
                logger.error(f"登录请求异常 (使用{proxy_info}): {str(e)}")
                return None
                
            # --- 第三步：从登录响应中提取最终cookie --- 
            logger.info(f"步骤3: 提取登录成功后的cookie (使用{proxy_info})...")
            final_cookies = {}
            
            # 优先使用登录后响应的 cookies
            login_response_cookies = login_res.cookies.get_dict()
            final_cookies.update(login_response_cookies)
            
            # 检查 Set-Cookie Header，因为它可能包含 HttpOnly 的 cookie
            set_cookie_header = login_res.headers.get('set-cookie')
            if set_cookie_header:
                logger.debug(f"登录响应包含set-cookie: {set_cookie_header[:100]}...")
                session_match = re.search(r'flarum_session=([^;]+)', set_cookie_header)
                if session_match:
                    final_cookies['flarum_session'] = session_match.group(1)
                    logger.debug(f"从set-cookie提取到session: {session_match.group(1)[:10]}...")
                remember_match = re.search(r'flarum_remember=([^;]+)', set_cookie_header)
                if remember_match:
                    final_cookies['flarum_remember'] = remember_match.group(1)
                    logger.debug(f"从set-cookie提取到remember: {remember_match.group(1)[:10]}...")
            
            # 确保 session cookie 存在
            if 'flarum_session' not in final_cookies:
                logger.warning(f"未能提取到最终的session cookie，尝试使用初始session cookie (使用{proxy_info})")
                final_cookies['flarum_session'] = session_cookie
                
            # 构建最终 cookie 字符串
            cookie_parts = [f"{k}={v}" for k, v in final_cookies.items() if v is not None] # 过滤掉 None 值
            cookie_str = "; ".join(cookie_parts)
            logger.info(f"最终cookie字符串: {cookie_str[:50]}... (使用{proxy_info})")
            
            # 验证cookie
            if not self._verify_cookie(req, cookie_str, proxy_info):
                 logger.error(f"登录后Cookie验证失败 (使用{proxy_info})")
                 return None
            
            logger.info(f"登录并验证Cookie成功 (使用{proxy_info})")
            return cookie_str
                
        except Exception as e:
            logger.error(f"登录过程出错 (使用{proxy_info}): {str(e)}")
            import traceback
            logger.error(f"详细错误: {traceback.format_exc()}")
            return None
            
    def _verify_cookie(self, req, cookie_str, proxy_info):
        """验证cookie是否有效"""
        try:
            if not cookie_str:
                logger.warning("尝试验证空cookie字符串")
                return None
                
            logger.info(f"验证cookie有效性 (使用{proxy_info})...")
            headers = {
                "Cookie": cookie_str,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
                "Accept": "*/*",
                "Cache-Control": "no-cache"
            }
            
            try:
                # 访问首页进行验证
                verify_res = req.get_res("https://pting.club", headers=headers)
                if not verify_res or verify_res.status_code != 200:
                    logger.error(f"验证cookie请求失败，状态码: {verify_res.status_code if verify_res else '无响应'} (使用{proxy_info})")
                    return None
            except Exception as e:
                logger.error(f"验证cookie请求异常 (使用{proxy_info}): {str(e)}")
                return None
                
            # 验证是否已登录（检查页面是否包含用户ID）
            pattern = r'"userId":(\d+)'
            user_matches = re.search(pattern, verify_res.text)
            if not user_matches:
                logger.error(f"验证cookie失败，响应中未找到userId (使用{proxy_info})")
                # 打印部分响应内容用于调试
                logger.debug(f"验证响应内容片段: {verify_res.text[:500] if verify_res else ''}")
                return None
                
            user_id = user_matches.group(1)
            if user_id == "0":
                logger.error(f"验证cookie失败，userId为0，表示未登录状态 (使用{proxy_info})")
                return None
                
            logger.info(f"Cookie验证成功，用户ID: {user_id} (使用{proxy_info})")
            return cookie_str # 返回验证通过的 cookie 字符串
        except Exception as e:
            logger.error(f"验证cookie过程出错 (使用{proxy_info}): {str(e)}")
            return None

    def _check_invites_with_cookie(self, cookie, max_retries=None, retry_delay=None):
        """使用获取到的Cookie检查待审核邀请"""
        if not cookie:
             logger.error("无效的Cookie，无法检查邀请")
             return
             
        if max_retries is None:
            max_retries = int(self._retry_count) 
        if retry_delay is None:
            retry_delay = int(self._retry_interval)

        # 初始化 approved_items 变量，确保在所有代码路径下都有定义
        approved_items = []

        main_fengchao_username = None
        fengchao_site_name = None
        try:
            if self.sites:
                fengchao_site_config = next((s for s in self.sites.get_indexers() if "pting.club" in s.get("url", "") or s.get("name", "").lower() == "fengchao"), None)
                if fengchao_site_config:
                    fengchao_site_name = fengchao_site_config.get("name", "Fengchao")
                    main_fengchao_username = fengchao_site_config.get("username")
                    if main_fengchao_username:
                        logger.info(f"获取到配置的蜂巢主用户名: {main_fengchao_username}")
                    else:
                        logger.warning(f"在站点 '{fengchao_site_name}' 配置中未找到主用户名 (username 字段)")
                else:
                    logger.warning("在 MoviePilot 配置中未找到蜂巢站点 (pting.club)")
            else:
                 logger.warning("SitesHelper 未初始化，无法获取主用户名")
        except Exception as e:
            logger.error(f"获取蜂巢主用户名时出错: {e}")

        url = "https://pting.club/api/store/invite/list"
        params = {
            'filter[query]': "",
            'filter[status]': "0",
            'page[offset]': "0"
        }
        headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
            'Cookie': cookie
        }
        
        proxies = self._get_proxies()
        req_utils = RequestUtils(
            proxies=proxies,
            timeout=30
        )
        proxy_info = "代理" if proxies else "直接连接"
        
        retries = 0
        while retries <= max_retries:
            try:
                logger.info(f"开始第 {retries+1}/{max_retries+1} 次尝试获取待审核邀请 (使用{proxy_info})...")
                response = req_utils.get_res(url, params=params, headers=headers)
                if not response or response.status_code != 200:
                    logger.error(f"获取待审核邀请失败，状态码：{response.status_code if response else '未知'} (使用{proxy_info})")
                    retries += 1
                    if retries <= max_retries:
                        logger.debug(f"第{retries}/{max_retries+1}次获取失败，将在 {retry_delay} 秒后重试...")
                        time.sleep(retry_delay)
                    continue
                
                try:
                    data = response.json()
                except Exception as e:
                    logger.error(f"解析邀请响应数据失败: {str(e)} (使用{proxy_info})")
                    retries += 1
                    if retries <= max_retries:
                        time.sleep(retry_delay)
                        continue
                    else:
                        break

                if data.get('data'):
                    logger.info(f"发现{len(data['data'])}个待审核邀请 (使用{proxy_info})")
                    notification_items = []
                    current_pending_details = {}
                    previous_pending_timestamps = {k: v.get('timestamp') for k, v in (self.get_data('pending_invites_details') or {}).items() if v.get('timestamp')}

                    items_to_process = list(data['data'])
                    approved_ids = set()
                    auto_approved_notification_items = []
                    pending_reviews = []
                    approved_items = [] # 修改：收集审核通过的详细信息

                    for item in items_to_process:
                        item_id = item['id']
                        attributes = item.get('attributes', {})
                        user = attributes.get('user', '未知')
                        api_email = attributes.get('email', '未知')
                        api_username = attributes.get('username', '未知')
                        link1 = attributes.get('link', '')
                        link2 = attributes.get('link2', '')
                        now_iso = datetime.now().isoformat()

                        is_main_account_invite = (api_email == self._username)

                        link1_result = self._get_invitee_details_and_judge(link1) if link1 else {}
                        link2_result = self._get_invitee_details_and_judge(link2) if link2 else {}

                        link1_status = {"verified": False, "username_match": False, "email_match": False, "level_ok": False, "error": None}
                        link2_status = {"verified": False, "username_match": False, "email_match": False, "level_ok": False, "error": None}
                        extracted_level1 = None
                        extracted_level2 = None

                        # --- 填充 link1_status 和 extracted_level1 ---
                        if link1_result:
                             if link1_result.get("error_reason"): link1_status["error"] = link1_result["error_reason"]
                             else:
                                extracted_username1 = link1_result.get("extracted_username", "")
                                extracted_email1 = link1_result.get("extracted_email", "")
                                extracted_level1 = link1_result.get("extracted_level", "") # 赋值
                                if api_username and extracted_username1 and api_username.lower() == extracted_username1.lower(): link1_status["username_match"] = True
                                if api_email and extracted_email1 and api_email.lower() == extracted_email1.lower(): link1_status["email_match"] = True
                                if extracted_level1 and extracted_level1 not in self.not_pass_levels: link1_status["level_ok"] = True
                                if link1_status["username_match"] and link1_status["email_match"] and link1_status["level_ok"]: link1_status["verified"] = True

                        # --- 填充 link2_status 和 extracted_level2 ---
                        if link2_result:
                             if link2_result.get("error_reason"): link2_status["error"] = link2_result["error_reason"]
                             else:
                                extracted_username2 = link2_result.get("extracted_username", "")
                                extracted_email2 = link2_result.get("extracted_email", "")
                                extracted_level2 = link2_result.get("extracted_level", "") # 赋值
                                if api_username and extracted_username2 and api_username.lower() == extracted_username2.lower(): link2_status["username_match"] = True
                                if api_email and extracted_email2 and api_email.lower() == extracted_email2.lower(): link2_status["email_match"] = True
                                if extracted_level2 and extracted_level2 not in self.not_pass_levels: link2_status["level_ok"] = True
                                if link2_status["username_match"] and link2_status["email_match"] and link2_status["level_ok"]: link2_status["verified"] = True

                        # --- 判断最终状态 ---
                        final_pass = False
                        if link1 and link2: final_pass = link1_status["verified"] and link2_status["verified"]
                        elif link1: final_pass = link1_status["verified"]
                        elif link2: final_pass = link2_status["verified"]

                        # --- 修改：构造 verified_link_details (包含两个链接的详情) ---
                        verified_link_details = {}
                        if final_pass:
                            if link1_status["verified"]:
                                verified_link_details['link1'] = {
                                    'username': link1_result.get("extracted_username", '未知'),
                                    'email': link1_result.get("extracted_email", '未知'),
                                    'level': link1_result.get("extracted_level", '未知')
                                }
                            if link2_status["verified"]:
                                verified_link_details['link2'] = {
                                    'username': link2_result.get("extracted_username", '未知'),
                                    'email': link2_result.get("extracted_email", '未知'),
                                    'level': link2_result.get("extracted_level", '未知')
                                }
                            # 如果 final_pass 但 verified_link_details 为空 (理论不应发生), 记录警告
                            if not verified_link_details:
                                logger.warning(f"邀请 ID: {item_id} final_pass 为 True 但 verified_link_details 为空。")


                        # --- 保存详细信息 ---
                        current_pending_details[item_id] = {
                            'timestamp': now_iso,
                            'inviter': user,
                            'invitee_email_api': api_email,
                            'invitee_username_api': api_username,
                            'link1': link1,
                            'link2': link2,
                            'is_main_account': is_main_account_invite,
                            'link1_extracted_username': link1_result.get("extracted_username") if link1_result else None,
                            'link1_extracted_email': link1_result.get("extracted_email") if link1_result else None,
                            'link1_extracted_level': extracted_level1 if link1_result else None,
                            'link1_status': link1_status,
                            'link2_extracted_username': link2_result.get("extracted_username") if link2_result else None,
                            'link2_extracted_email': link2_result.get("extracted_email") if link2_result else None,
                            'link2_extracted_level': extracted_level2 if link2_result else None,
                            'link2_status': link2_status,
                            'final_pass_status': final_pass
                        }

                        is_new = item_id not in previous_pending_timestamps
                        is_overtime = False
                        if not is_new:
                            last_timestamp_str = previous_pending_timestamps.get(item_id)
                            if last_timestamp_str:
                                try:
                                    last_time_dt = datetime.fromisoformat(last_timestamp_str)
                                    if (datetime.now(last_time_dt.tzinfo) - last_time_dt).total_seconds() > 4 * 3600:
                                        is_overtime = True
                                except ValueError:
                                    logger.warning(f"无法解析上次记录的时间戳: {last_timestamp_str}")
                                    is_overtime = True

                        if is_new or is_overtime:
                            notification_items.append({
                                "邀请人": user,
                                "受邀人邮箱(API)": api_email,
                                "受邀人用户名(API)": api_username,
                                "链接1": link1,
                                "链接2": link2,
                                "链接1用户名": link1_result.get("extracted_username") if link1_result else 'N/A',
                                "链接1邮箱": link1_result.get("extracted_email") if link1_result else 'N/A',
                                "链接1等级": extracted_level1 if link1_result else 'N/A',
                                "链接1状态": link1_status,
                                "链接2用户名": link2_result.get("extracted_username") if link2_result else 'N/A',
                                "链接2邮箱": link2_result.get("extracted_email") if link2_result else 'N/A',
                                "链接2等级": extracted_level2 if link2_result else 'N/A',
                                "链接2状态": link2_status,
                                "最终状态": "通过" if final_pass else "不通过",
                                "通知原因": "新邀请" if is_new else "超过4小时未审核",
                                "is_main_account": is_main_account_invite
                            })
                            logger.debug(f"{ '新增' if is_new else '超时' }待审核邀请，准备通知: {item_id} (使用{proxy_info}){' (主账号)' if is_main_account_invite else ''}, 最终判断: {'通过' if final_pass else '不通过'}")

                        # --- 新的自动审核逻辑 ---
                        perform_auto_approve = False
                        level_to_check = '' # 用于检查 VIP
                        if self._auto_approve_enabled and final_pass and verified_link_details:
                            # 获取任一验证通过链接的等级用于 VIP 检查
                            if 'link1' in verified_link_details:
                                level_to_check = verified_link_details['link1'].get('level', '').lower()
                            elif 'link2' in verified_link_details:
                                level_to_check = verified_link_details['link2'].get('level', '').lower()

                            if "vip" in level_to_check:
                                logger.info(f"邀请 ID: {item_id} 验证通过但等级含 VIP ({level_to_check.upper()})，不进行自动审核。")
                            else:
                                perform_auto_approve = True
                        elif self._auto_approve_enabled and final_pass and not verified_link_details:
                             logger.warning(f"邀请 ID: {item_id} 验证通过但未能构造 verified_link_details，无法自动审核。")


                        if perform_auto_approve:
                            logger.info(f"邀请 ID: {item_id} 满足自动审核条件，尝试自动通过...")
                            csrf_token = self._get_csrf_token(req_utils, cookie)
                            if csrf_token:
                                # --- 修改：调用新的自动审核函数，传递 verified_link_details ---
                                if self._auto_approve_invite(req_utils, int(item_id), verified_link_details, cookie, csrf_token):
                                    logger.info(f"邀请 ID: {item_id} 自动审核成功！")
                                    # --- 修改：approved_items 存储 verified_link_details ---
                                    approved_items.append({
                                        "invite_id": item_id,
                                        "verified_details": verified_link_details,
                                        # 也存储 API 信息以备用
                                        "api_username": api_username,
                                        "api_email": api_email
                                    })
                                    current_pending_details.pop(item_id, None)
                                    continue # 跳过后续添加到 pending_reviews 的步骤
                                else:
                                    logger.error(f"邀请 ID: {item_id} 自动审核 API 调用失败，将按正常流程处理（保存并通知）。")
                            else:
                                logger.error(f"未能获取 CSRF 令牌，无法为邀请 ID {item_id} 尝试自动审核。")

                        # 如果没有被自动审核成功并 continue，则添加到待处理列表 (逻辑不变)
                        if any(i.get('id') == item_id for i in items_to_process):
                             pending_reviews.append(item)


                    # --- 循环结束后 ---
                    # 发送待审核邀请通知 (逻辑不变，但 TODO 部分已修正)
                    if notification_items and self._notify:
                        final_notification_items = [
                            n_item for n_item in notification_items
                            # 使用 n_item['id'] 或 n_item.get('id', 'some_default_if_missing')
                            # 假设 notification_items 里的 id 字段与 item_id 对应
                            if not any(a_item['invite_id'] == n_item.get("id") for a_item in approved_items)
                        ]
                        if final_notification_items:
                             self._send_invites_notification(final_notification_items)


                    # 保存最终的待处理详情 (逻辑不变)
                    self.save_data('pending_invites_details', current_pending_details)

                else:
                    logger.info(f"没有待审核的邀请 (使用{proxy_info})")
                    if self.get_data('pending_invites_details'):
                        self.save_data('pending_invites_details', {})
                        logger.info("已清空存储的待审核邀请详情")

                break # 成功获取并处理后退出重试循环

            except Exception as e:
                logger.error(f"检查待审核邀请过程中发生异常: {str(e)} (使用{proxy_info})")
                logger.error(traceback.format_exc())
                retries += 1
                if retries <= max_retries:
                    logger.debug(f"发生异常，将在 {retry_delay} 秒后进行第 {retries+1}/{max_retries+1} 次重试...")
                    time.sleep(retry_delay)
                else:
                    logger.error(f"已达到最大重试次数 ({max_retries+1})，请求失败 (使用{proxy_info})")
                    break

        # --- 函数末尾 ---
        # 发送自动审核通过的通知 (逻辑不变，但会调用更新后的 _send_auto_approval_notification)
        if approved_items:
            self._send_auto_approval_notification(approved_items)

        # 发送待审核邀请的通知 (注释掉的逻辑保持不变)
        # ...

    def _send_invites_notification(self, items):
        """
        发送待审核邀请通知 (格式不变)
        """
        if not items:
            return
            
        try:
            title = f"【蜂巢论坛】{len(items)} 条待审核邀请提醒"
            
            # 构建纯文本通知内容
            text_lines = [f"🐝 蜂巢论坛发现 {len(items)} 条待审核邀请："] 
            
            for i, item in enumerate(items, 1):
                is_main = item.get("is_main_account", False)
                main_account_tag = "(主账号邀请)" if is_main else ""
                final_status = item.get("最终状态", "未知")
                status_icon = "✅" if final_status == "通过" else "❌" if final_status == "不通过" else "❓"
                
                # 使用空行和更清晰的分隔符
                text_lines.append("\n------------------------------")
                text_lines.append(f"【{i}】{item.get('通知原因')} {main_account_tag} {status_icon}{final_status}")
                text_lines.append(f"邀请人: {item.get('邀请人', '未知')}")
                text_lines.append(f"受邀人(API): {item.get('受邀人用户名(API)', '?')} / {item.get('受邀人邮箱(API)', '?')}")
                text_lines.append("") # 添加空行增加间距
                
                # 链接1 详情
                link1 = item.get('链接1', '')
                text_lines.append("🔗 链接1: " + (f' {link1} ' if link1 else "无")) # 链接前后加空格
                if link1:
                    l1_status = item.get('链接1状态', {})
                    l1_error = l1_status.get('error')
                    if l1_error:
                         text_lines.append(f"  └─ 验证失败: {l1_error}")
                    else:
                        l1_user = item.get('链接1用户名', 'N/A')
                        l1_email = item.get('链接1邮箱', 'N/A')
                        l1_level = item.get('链接1等级', 'N/A')
                        l1_user_match = "✅" if l1_status.get('username_match') else "❌"
                        l1_email_match = "✅" if l1_status.get('email_match') else "❌"
                        l1_level_ok = "✅" if l1_status.get('level_ok') else "❌"
                        text_lines.append(f"  └─ 提取: 用户={l1_user}({l1_user_match}{'匹配' if l1_status.get('username_match') else '不符'}) | "
                                          f"邮箱={l1_email}({l1_email_match}{'匹配' if l1_status.get('email_match') else '不符'}) | "
                                          f"等级={l1_level}({l1_level_ok}{'通过' if l1_status.get('level_ok') else '不符'})")
                text_lines.append("") # 添加空行

                # 链接2 详情
                link2 = item.get('链接2', '')
                text_lines.append("🔗 链接2: " + (f' {link2} ' if link2 else "无")) # 链接前后加空格
                if link2:
                    l2_status = item.get('链接2状态', {})
                    l2_error = l2_status.get('error')
                    if l2_error:
                         text_lines.append(f"  └─ 验证失败: {l2_error}")
                    else:
                        l2_user = item.get('链接2用户名', 'N/A')
                        l2_email = item.get('链接2邮箱', 'N/A')
                        l2_level = item.get('链接2等级', 'N/A')
                        l2_user_match = "✅" if l2_status.get('username_match') else "❌"
                        l2_email_match = "✅" if l2_status.get('email_match') else "❌"
                        l2_level_ok = "✅" if l2_status.get('level_ok') else "❌"
                        text_lines.append(f"  └─ 提取: 用户={l2_user}({l2_user_match}{'匹配' if l2_status.get('username_match') else '不符'}) | "
                                          f"邮箱={l2_email}({l2_email_match}{'匹配' if l2_status.get('email_match') else '不符'}) | "
                                          f"等级={l2_level}({l2_level_ok}{'通过' if l2_status.get('level_ok') else '不符'})")
            
            text_lines.append("\n------------------------------")
            text_lines.append("\n请尽快处理。")
            text = "\n".join(text_lines) 
            
            # 发送通知 (调用 send_msg)
            self.send_msg(title=title, text=text)
            logger.info(f"已发送 {len(items)} 个待审核邀请通知 (纯文本格式)")
            
        except Exception as e:
            logger.error(f"发送纯文本通知失败: {str(e)}")

    def _send_auto_approval_notification(self, approved_items: List[Dict[str, Any]]):
        """发送自动审核成功的通知 (改进格式和内容)"""
        if not self._notify or not approved_items:
            return

        count = len(approved_items)
        title = f"✅ 蜂巢论坛：{count} 个邀请已自动审核通过"
        
        text_lines = [f"🐝 以下 {count} 个邀请已通过验证并自动审核通过："]

        for i, item in enumerate(approved_items, 1):
            invite_id = item.get('invite_id', '未知')
            details = item.get('verified_details', {})
            api_user = item.get('api_username', '?')
            api_email = item.get('api_email', '?')
            
            text_lines.append(f"\n=== 【{i}】ID: {invite_id} ===")
            text_lines.append(f"📝 API信息: 用户={api_user} | 邮箱={api_email}")

            verified_links = []
            if 'link1' in details:
                verified_links.append("链接1")
            if 'link2' in details:
                verified_links.append("链接2")
            
            text_lines.append(f"✅ 验证通过: {', '.join(verified_links)}")
            
            if 'link1' in details:
                l1_info = details['link1']
                l1_user = l1_info.get('username', '未知')
                l1_email = l1_info.get('email', '未知')
                l1_level = l1_info.get('level', '未知')
                text_lines.append("🔗 链接1验证结果:")
                text_lines.append(f"   👤 用户: {l1_user}")
                text_lines.append(f"   📧 邮箱: {l1_email}")
                text_lines.append(f"   🏅 等级: {l1_level}")
            else:
                text_lines.append("🔗 链接1: 未验证或未提供")

            if 'link2' in details:
                l2_info = details['link2']
                l2_user = l2_info.get('username', '未知')
                l2_email = l2_info.get('email', '未知')
                l2_level = l2_info.get('level', '未知')
                text_lines.append("🔗 链接2验证结果:")
                text_lines.append(f"   👤 用户: {l2_user}")
                text_lines.append(f"   📧 邮箱: {l2_email}")
                text_lines.append(f"   🏅 等级: {l2_level}")
            else:
                text_lines.append("🔗 链接2: 未验证或未提供")

        text_lines.append("\n💬 备注已提交至蜂巢论坛，包含所有验证细节。")
        text = "\n".join(text_lines)

        self.send_msg(title, text, self.plugin_icon)
        logger.info(f"已发送 {count} 个邀请自动审核通过的通知。")

    def send_msg(self, title, text="", image=""):
        """发送消息 (逻辑不变)"""
        if not self._notify:
            return
        
        try:
            self.post_message(mtype=NotificationType.SiteMessage, title=title, text=text)
        except Exception as e:
            logger.error(f"发送通知失败: {str(e)}")

    def _get_invitee_details_and_judge(self, invite_url: str) -> Dict[str, str]:
        """访问邀请链接提取信息 (逻辑不变)"""
        # 返回的字典结构
        result = {
            "extracted_email": "无法访问/提取",
            "extracted_level": "无法访问/提取",
            "extracted_username": "无法访问/提取", # 新增字段
            "error_reason": None 
        }

        if not invite_url or not self.sites:
            logger.warning(f"邀请链接为空或 SitesHelper 未初始化，无法提取信息")
            result["error_reason"] = "链接为空或插件未就绪"
            return result

        # --- 解析链接，查找匹配站点，获取Cookie和UA (这部分逻辑不变) --- 
        try:
            parsed_url = urlparse(invite_url)
            hostname = parsed_url.netloc
        except Exception as e:
            logger.error(f"解析邀请链接失败: {invite_url}, 错误: {e}")
            result["error_reason"] = f"链接解析失败: {e}"
            return result

        matched_site = None
        site_cookie = None
        site_ua = None
        site_name_for_log = "未知站点"
        try:
            for site in self.sites.get_indexers():
                 site_url_config = site.get("url")
                 if not site_url_config:
                      continue
                 site_hostname = urlparse(site_url_config).netloc
                 site_name_for_log = site.get('name', '未知站点')
                 
                 if hostname == site_hostname:
                      matched_site = site
                      logger.info(f"找到匹配站点: {site_name_for_log} for url: {invite_url}")
                      site_cookie = matched_site.get("cookie")
                      site_ua = matched_site.get("ua")
                      if not site_cookie:
                          logger.warning(f"站点 {site_name_for_log} 已找到，但未配置 Cookie")
                      else:
                          logger.info(f"获取到站点 {site_name_for_log} 的 Cookie")
                      break
        except Exception as e:
             logger.error(f"查找匹配站点时出错: {e}")
             result["error_reason"] = f"查找站点配置出错: {e}"
             return result

        if not matched_site:
            logger.warning(f"未找到与邀请链接 {invite_url} 域名匹配的已配置站点")
            result["error_reason"] = "未找到匹配的 MoviePilot 站点"
            return result
            
        if not site_cookie:
            logger.warning(f"站点 {matched_site.get('name', '未知')} 未配置 Cookie，无法访问链接 {invite_url}")
            result["error_reason"] = f"匹配站点 ({matched_site.get('name', '未知')}) 未配置 Cookie"
            return result

        # --- 准备请求 --- 
        proxies = self._get_proxies()
        request_headers = {
            'User-Agent': site_ua or settings.USER_AGENT, 
            'Cookie': site_cookie, 
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'Cache-Control': 'max-age=0',
            # 'Referer': matched_site.get("url") # Referer 有时会导致问题，先去掉试试
        }
        req_proxies = None
        if proxies and isinstance(proxies, dict) and proxies.get('http'):
             req_proxies = {'http': proxies['http'], 'https': proxies['http']}
        elif proxies and isinstance(proxies, str):
             req_proxies = {'http': proxies, 'https': proxies}

        req_utils = RequestUtils(headers=request_headers, proxies=req_proxies, timeout=45) # 增加超时
        proxy_info = "代理" if req_proxies else "直接连接"

        # --- 访问邀请链接并提取信息 --- 
        try:
            logger.info(f"尝试访问邀请链接: {invite_url} (使用站点 {matched_site.get('name')} 的Cookie和{proxy_info})")
            # 尝试禁用SSL验证，某些站点可能证书有问题
            response = req_utils.get_res(invite_url, verify=False)
            
            if response is None:
                logger.error(f"访问邀请链接失败，无响应 (站点: {matched_site.get('name')}, {proxy_info})")
                result["error_reason"] = f"访问链接无响应"
                return result
                
            # 检查是否因为Cookie无效导致重定向到登录页
            if response.status_code in [301, 302, 307] and 'login.php' in response.headers.get('Location', ''):
                 logger.error(f"访问邀请链接失败，Cookie可能无效，重定向到登录页 (站点: {matched_site.get('name')}, {proxy_info})")
                 result["error_reason"] = f"Cookie无效(重定向到登录页)"
                 return result
            elif response.status_code != 200:
                logger.error(f"访问邀请链接失败，状态码: {response.status_code} (站点: {matched_site.get('name')}, {proxy_info})")
                # 记录部分响应内容帮助诊断
                try:
                     error_text = response.text[:300]
                     logger.debug(f"访问失败响应内容片段: {error_text}")
                except Exception:
                     logger.debug("无法读取访问失败的响应内容")
                result["error_reason"] = f"访问链接失败 (状态码: {response.status_code})"
                return result

            html_content = response.text
            # 检查页面内容是否过短，可能为空白页或错误页
            if len(html_content) < 500:
                logger.warning(f"访问邀请链接 {invite_url} 返回内容过短 ({len(html_content)} bytes)，可能不是有效的用户详情页。")
                # 尝试记录内容片段
                logger.debug(f"过短响应内容片段: {html_content[:300]}")
                result["error_reason"] = f"页面内容过短，可能无效"
                # 虽然内容短，但仍然尝试提取，万一有用呢

            logger.info(f"成功访问邀请链接: {invite_url}, 页面长度: {len(html_content)}")
            
            # 使用 BeautifulSoup 解析 HTML
            soup = BeautifulSoup(html_content, 'html.parser')

            # --- 提取用户名 --- 
            # 油猴脚本 XPath: //*[@id="outer"]//h1//b
            # CSS Selector: #outer h1 b
            username_tag = soup.select_one('#outer h1 b')
            if username_tag:
                result["extracted_username"] = username_tag.get_text(strip=True)
                logger.info(f"提取到用户名 (h1 b): {result['extracted_username']}")
            else:
                # 备选方案：查找页面标题中的用户名 (可能不准)
                title_text = soup.title.string if soup.title else ""
                # 假设标题格式类似 "用户详情 - 用户名" 或 "用户名 - 用户详情"
                username_match_title = re.search(r'(?:用户详情\s*-\s*|Details\s*for\s*|User\s*details\s*-\s*)(.+?)(?:\s*-|\s*\$|$)', title_text, re.I)
                if username_match_title:
                     result["extracted_username"] = username_match_title.group(1).strip()
                     logger.info(f"提取到用户名 (备选 title): {result['extracted_username']}")
                else:
                     logger.warning(f"在链接 {invite_url} 未找到用户名信息 (#outer h1 b 或 title)")
                     result["extracted_username"] = "未提取到用户名"

            # --- 提取邮箱 --- 
            # 查找 mailto: 链接
            email_tag = soup.find('a', href=lambda href: href and href.startswith('mailto:'))
            if email_tag:
                result["extracted_email"] = email_tag.get_text(strip=True) or email_tag['href'].split(':')[1]
                logger.info(f"提取到邮箱 (mailto): {result['extracted_email']}")
            else:
                # 备选方案：尝试从表格单元格提取
                email_td = soup.find('td', string=re.compile(r'邮箱|Email', re.I))
                if email_td and email_td.find_next_sibling('td'):
                    email_sibling_td = email_td.find_next_sibling('td')
                    email_tag_in_td = email_sibling_td.find('a', href=lambda href: href and href.startswith('mailto:'))
                    if email_tag_in_td:
                        result["extracted_email"] = email_tag_in_td.get_text(strip=True) or email_tag_in_td['href'].split(':')[1]
                        logger.info(f"提取到邮箱 (备选 td mailto): {result['extracted_email']}")
                    elif '@' in email_sibling_td.get_text(strip=True): # 简单判断是否像邮箱
                        result["extracted_email"] = email_sibling_td.get_text(strip=True)
                        logger.info(f"提取到邮箱 (备选 td text): {result['extracted_email']}")
                    else:
                        logger.warning(f"在链接 {invite_url} 未找到邮箱信息 (mailto 或 td)")
                        # --- 新增 Regex 备选 ---
                        email_regex = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                        # 在整个HTML中查找第一个匹配的邮箱
                        regex_match = re.search(email_regex, html_content)
                        if regex_match:
                            result["extracted_email"] = regex_match.group(0)
                            logger.info(f"提取到邮箱 (备选 Regex): {result['extracted_email']}")
                        else:
                            logger.warning(f"在链接 {invite_url} 未找到邮箱信息 (mailto, td, 或 regex)")
                            result["extracted_email"] = "未提取到邮箱"
                        # --- Regex 备选结束 ---
                else:
                    logger.warning(f"在链接 {invite_url} 未找到邮箱信息 (mailto 或 td)")
                    result["extracted_email"] = "未提取到邮箱"

            # --- 提取等级 --- 
            # 严格按照脚本逻辑: 找包含"等级"的td -> 找兄弟td -> 找里面的img -> 取title
            level_td_label = soup.find('td', string=re.compile(r'等级|Class', re.I)) # 大小写不敏感
            extracted_level_text = "未提取到等级"
            if level_td_label and level_td_label.find_next_sibling('td'):
                level_td_value = level_td_label.find_next_sibling('td')
                level_img_in_td = level_td_value.find('img', title=True)
                if level_img_in_td and level_img_in_td['title']:
                    extracted_level_text = level_img_in_td['title'].strip()
                    logger.info(f"提取到等级 (img title): {extracted_level_text}")
                else:
                    # 如果没有图片，尝试直接获取单元格文本
                    level_text_in_td = level_td_value.get_text(strip=True)
                    if level_text_in_td:
                        extracted_level_text = level_text_in_td
                        logger.warning(f"在等级单元格中未找到 img[title]，使用单元格文本作为备选: {extracted_level_text}")
                    else:
                        logger.warning(f"在链接 {invite_url} 的等级单元格中未找到 img[title] 或有效文本")
            else:
                logger.warning(f"在链接 {invite_url} 未找到等级信息 (未找到'等级'单元格或其兄弟单元格)")
            
            result["extracted_level"] = extracted_level_text

            # 如果都无法提取，记录错误
            if result["extracted_email"] == "无法访问/提取" and result["extracted_level"] == "无法访问/提取" and result["extracted_username"] == "无法访问/提取":
                 result["error_reason"] = "页面访问成功但无法提取用户名、邮箱和等级"

            return result

        except requests.exceptions.Timeout:
            logger.error(f"访问邀请链接 {invite_url} 超时 (站点: {matched_site.get('name')}, {proxy_info})")
            result["error_reason"] = "访问链接超时"
            return result
        except requests.exceptions.RequestException as e:
            logger.error(f"访问邀请链接 {invite_url} 发生网络错误: {e} (站点: {matched_site.get('name')}, {proxy_info})")
            result["error_reason"] = f"网络错误: {e}"
            return result
        except Exception as e:
            logger.error(f"处理邀请链接 {invite_url} 时发生未知异常: {e}")
            logger.error(traceback.format_exc())
            result["error_reason"] = f"处理异常: {e}"
            return result

    def _get_csrf_token(self, req_utils: RequestUtils, cookie: str) -> Optional[str]:
        """获取 CSRF 令牌 (逻辑不变)"""
        try:
            logger.debug("尝试获取最新的 CSRF 令牌...")
            get_headers = {
                "Accept": "*/*",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
                "Cache-Control": "no-cache",
                "Cookie": cookie
            }
            res = req_utils.get_res("https://pting.club", headers=get_headers)
            if not res or res.status_code != 200:
                logger.error(f"获取 CSRF 令牌失败，状态码: {res.status_code if res else '无响应'}")
                return None

            # 优先从 Header 获取
            csrf_token = res.headers.get('x-csrf-token')
            if csrf_token:
                logger.debug(f"从 Header 获取到 CSRF 令牌: {csrf_token}")
                return csrf_token

            # 其次从 HTML 获取
            pattern = r'"csrfToken":"(.*?)"'
            csrf_matches = re.findall(pattern, res.text)
            if csrf_matches:
                csrf_token = csrf_matches[0]
                logger.debug(f"从 HTML 获取到 CSRF 令牌: {csrf_token}")
                return csrf_token

            logger.error("无法从响应中提取 CSRF 令牌")
            return None
        except Exception as e:
            logger.error(f"获取 CSRF 令牌时发生异常: {str(e)}")
            return None

    def _auto_approve_invite(self, req_utils: RequestUtils, invite_id: int, verified_details: Dict[str, Dict[str, str]], cookie: str, csrf_token: str) -> bool:
        """
        调用 API 自动通过邀请审核 (使用双链接详情)。
        :param req_utils: RequestUtils 实例。
        :param invite_id: 邀请 ID。
        :param verified_details: 包含已验证链接详情的字典, e.g., {'link1': {...}, 'link2': {...}}。
        :param cookie: Cookie 字符串。
        :param csrf_token: CSRF 令牌。
        :return: True 如果成功, False 如果失败。
        """
        if not all([req_utils, invite_id, verified_details, cookie, csrf_token]):
            logger.error(f"自动审核参数不足 (ID: {invite_id})，无法执行。verified_details: {bool(verified_details)}")
            return False

        url = "https://pting.club/api/store/invite/edit"
        
        # --- 构造更详细的备注 ---
        remark_parts = ["自动审核通过"]
        if 'link1' in verified_details:
            l1 = verified_details['link1']
            remark_parts.append(f"L1: U={l1.get('username','?')}, E={l1.get('email','?')}, L={l1.get('level','?')} ✅")
        if 'link2' in verified_details:
            l2 = verified_details['link2']
            remark_parts.append(f"L2: U={l2.get('username','?')}, E={l2.get('email','?')}, L={l2.get('level','?')} ✅")
        
        remark = " | ".join(remark_parts)
        # 限制备注长度，以防超出 API 限制 (假设限制 255)
        max_remark_len = 250 
        if len(remark) > max_remark_len:
            remark = remark[:max_remark_len] + "..."
            
        payload = {
            "id": int(invite_id),
            "status": 1, # 1 表示通过
            "confirmRemark": remark # 使用包含双链接细节的备注
        }
        headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
            'x-csrf-token': csrf_token,
            'Cookie': cookie,
            'Content-Type': 'application/json; charset=utf-8',
            'Accept': 'application/json, text/plain, */*'
        }
        proxy_info = "代理" if req_utils._proxies else "直接连接"

        try:
            # 日志中也体现是基于双链接审核
            log_user_level = "未知"
            if 'link1' in verified_details: log_user_level = f"{verified_details['link1'].get('username','?')}({verified_details['link1'].get('level','?')})"
            elif 'link2' in verified_details: log_user_level = f"{verified_details['link2'].get('username','?')}({verified_details['link2'].get('level','?')})"
            
            logger.info(f"尝试自动审核通过邀请 ID: {invite_id} (基于验证通过的链接: {list(verified_details.keys())}, 用户/等级: {log_user_level}, 使用 {proxy_info})...")
            response = req_utils.put_res(url, json=payload, headers=headers)

            if response is None:
                logger.error(f"自动审核 API 请求失败，无响应 (ID: {invite_id}, 使用 {proxy_info})")
                return False

            if response.status_code == 200:
                logger.info(f"自动审核邀请 ID: {invite_id} 成功 (状态码: 200)。API响应: {response.text[:200]}")
                return True
            else:
                logger.error(f"自动审核 API 请求失败，状态码: {response.status_code} (ID: {invite_id}, 使用 {proxy_info})")
                logger.debug(f"失败响应内容: {response.text[:300]}")
                return False

        except Exception as e:
            logger.error(f"自动审核 API 请求时发生异常 (ID: {invite_id}, 使用 {proxy_info}): {str(e)}")
            logger.error(traceback.format_exc())
            return False


plugin_class = LuckPTAutoReview