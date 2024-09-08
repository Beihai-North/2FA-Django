import base64
from io import BytesIO

import qrcode
from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from .serializers import UserSerializer
from django_otp.plugins.otp_totp.models import TOTPDevice
from django.contrib.auth import authenticate

# 用户注册视图：处理用户注册请求
# 对应 API：POST /api/register/
class RegisterAPIView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

# 登录视图：通过用户名和密码登录，返回 JWT 令牌
# 对应 API：POST /api/login/
@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    username = request.data.get('username')
    password = request.data.get('password')

    # 验证用户名和密码
    user = authenticate(username=username, password=password)
    if user is None:
        return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

    user = User.objects.get(username=username)
    user_id = user.id  # 获取用户的 ID

    # 检查用户是否启用了 2FA
    totp_device = TOTPDevice.objects.filter(user_id=user_id,confirmed=1).first()

    if totp_device:
        # 如果用户启用了 2FA，返回标志，要求用户进一步验证 OTP
        return Response({
            "detail": "2FA required",
            "2fa_required": True
        }, status=status.HTTP_200_OK)
    else:
        # 如果用户没有启用 2FA，则直接返回 JWT 令牌
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh_token': str(refresh),
            'access_token': str(refresh.access_token),
        }, status=status.HTTP_200_OK)

# 登出视图：注销用户并将 JWT 令牌加入黑名单
# 对应 API：POST /api/logout/
@api_view(['POST'])
def logout_view(request):
    try:
        refresh_token = request.data.get("refresh", None)
        if not refresh_token:
            return Response({"detail": "Refresh token is missing"}, status=status.HTTP_400_BAD_REQUEST)

        token = RefreshToken(refresh_token)
        token.blacklist()  # 将刷新令牌加入黑名单

        return Response({"detail": "Logout successful"}, status=status.HTTP_205_RESET_CONTENT)  # 返回 205 状态码，带有详细信息
    except Exception as e:
        return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)  # 返回错误消息


# 禁用 TOTP 设备：删除用户的所有已确认 TOTP 设备
# 对应 API：POST /api/2fa/disable/
@api_view(['POST'])
@permission_classes([IsAuthenticated])  # 需要用户已认证
def disable_2fa(request):
    try:
        # 查找用户
        user = User.objects.get(username=request.user.username)
    except User.DoesNotExist:
        return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

    # 删除用户的所有已确认 TOTP 设备
    TOTPDevice.objects.filter(user_id=user.id, confirmed=True).delete()

    return Response({"message": "2FA disabled"}, status=status.HTTP_200_OK)

# 对应 API：GET /api/2fa/qr/
# 生成 2FA 二维码：用户扫描二维码后可以使用 Microsoft Authenticator 设置 TOTP
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def generate_2fa_qr(request):
    try:
        # 查找用户
        user = User.objects.get(username=request.user)
    except User.DoesNotExist:
        return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)
    # 获取或创建一个未确认的 TOTP 设备
    totp_device, created = TOTPDevice.objects.get_or_create(user_id=user.id, confirmed=True)

    # 获取 otpauth URL，该 URL 将生成二维码以供用户扫描
    qr_url = totp_device.config_url  # otpauth:// URL

    # 使用 qrcode 生成二维码
    qr = qrcode.make(qr_url)
    buffer = BytesIO()

    # 保存二维码到 BytesIO 中，没有指定格式的参数
    qr.save(buffer)

    # 将二维码图像转换为 Base64 编码
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    # 返回 Base64 编码的二维码图像
    return Response({
        'qr_code': qr_code_base64,
        'otp_auth_url': qr_url
    })


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_2fa(request):
    otp = request.data.get('otp')  # 获取用户输入的 OTP 动态验证码
    username = request.data.get('username')  # 获取用户名

    # 检查输入
    if not username or not otp:
        return Response({"detail": "Username and OTP are required."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # 查找用户
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

    try:
        # 查找 TOTP 设备
        totp_device = TOTPDevice.objects.get(user_id=user.id, confirmed=1)
    except TOTPDevice.DoesNotExist:
        return Response({"detail": "No TOTP device found for user."}, status=status.HTTP_400_BAD_REQUEST)

    # 验证 OTP
    if totp_device.verify_token(otp):
        # 验证成功，生成 JWT 令牌
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh_token': str(refresh),
            'access_token': str(refresh.access_token),
        }, status=status.HTTP_200_OK)
    else:
        return Response({"detail": "Invalid OTP code."}, status=status.HTTP_401_UNAUTHORIZED)
