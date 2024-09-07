from django.contrib.auth.models import User
from rest_framework import serializers

# 用户序列化器：用于用户注册和用户数据返回
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password')  # 包含的字段
        extra_kwargs = {'password': {'write_only': True}}  # 密码仅用于写入，不显示

    # 创建新用户时，使用 Django 内置的 create_user 方法
    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user
