from django.urls import path
from .views import RegisterAPIView, login_view, logout_view, disable_2fa, generate_2fa_qr, verify_2fa,check_2fa_status_view

# accounts 应用中的 API 路由配置
urlpatterns = [
    path('register/', RegisterAPIView.as_view(), name='register'),  # 注册 API
    path('login/', login_view, name='login'),  # 登录 API
    path('logout/', logout_view, name='logout'),  # 登出 API
    path('2fa/enable/', disable_2fa, name='disable_2fa'),  # 启用/禁用 TOTP 2FA
    path('2fa/check-2fa-status/', check_2fa_status_view, name='check_2fa_status'),
    path('2fa/qr/', generate_2fa_qr, name='generate_2fa_qr'),  # 生成 TOTP 二维码
    path('2fa/verify_2fa/', verify_2fa, name='verify_2fa'),  # 验证 TOTP 令牌
]
