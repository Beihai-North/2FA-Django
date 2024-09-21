from django_otp.plugins.otp_totp.models import TOTPDevice


def is_2fa_enabled(user):
    """
    检查指定用户是否启用了 2FA
    :param user: 用户对象
    :return: 如果启用了 2FA 返回 True，否则返回 False
    """
    user_id = user.id  # 获取用户的 ID
    totp_device = TOTPDevice.objects.filter(user_id=user_id, confirmed=True).first()
    return totp_device is not None
