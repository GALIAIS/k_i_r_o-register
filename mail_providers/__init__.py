"""
邮件服务抽象层 - 支持多种临时邮箱服务切换

使用方式:
    from mail_providers import get_provider, list_providers
    provider = get_provider("tempforward", base_url="http://...")
    email = provider.create_mailbox()
    otp = provider.wait_otp(timeout=90)

添加新服务:
    1. 在 mail_providers/ 下新建 py 文件
    2. 继承 MailProvider 实现三个方法
    3. 在本文件 PROVIDERS 中注册
"""
from .base import MailProvider
from .shiromail import ShiroMailProvider
from .tempforward import TempForwardProvider
from .yydsmail import YydsMailProvider

PROVIDERS: dict[str, type[MailProvider]] = {
    "shiromail": ShiroMailProvider,
    "tempforward": TempForwardProvider,
    "yydsmail": YydsMailProvider,
}


def get_provider(name: str, **kwargs) -> MailProvider:
    """根据名称创建邮件服务实例"""
    cls = PROVIDERS.get(name)
    if not cls:
        raise ValueError(f"未知邮件服务: {name}, 可选: {list(PROVIDERS.keys())}")
    return cls(**kwargs)


def list_providers() -> list[dict]:
    """返回所有已注册的邮件服务信息"""
    return [{"name": cls.name, "display_name": cls.display_name} for cls in PROVIDERS.values()]
