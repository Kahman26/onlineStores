from rest_framework import serializers
from .models import GoodCategory, Good, GoodImage, PaymentMethod, DeliveryMethod, Recipient, BasketItem, Checkout, \
    CheckoutItem, Transaction
import json


class GoodCategorySerializer(serializers.ModelSerializer):
    parentId = serializers.PrimaryKeyRelatedField(
        source='parent', queryset=GoodCategory.objects.all(), required=False, allow_null=True
    )

    class Meta:
        model = GoodCategory
        fields = ['id', 'title', 'description', 'parentId']


class GoodImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = GoodImage
        fields = ['id', 'image', 'thumbnail']


class GoodSerializer(serializers.ModelSerializer):
    categoryId = serializers.PrimaryKeyRelatedField(
        source='category', queryset=GoodCategory.objects.all()
    )
    sellerId = serializers.PrimaryKeyRelatedField(
        source='seller', read_only=True
    )
    images = GoodImageSerializer(many=True, read_only=True)
    uploaded_images = serializers.ListField(
        child=serializers.ImageField(), write_only=True, required=False
    )

    class Meta:
        model = Good
        fields = [
            'id', 'name', 'description', 'price',
            'categoryId', 'sellerId', 'images', 'uploaded_images'
        ]

    def create(self, validated_data):
        uploaded_images = validated_data.pop('uploaded_images', [])
        good = Good.objects.create(**validated_data)
        for image in uploaded_images:
            GoodImage.objects.create(good=good, image=image)
        return good


class PaymentMethodSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentMethod
        fields = ['id', 'title', 'description', 'logo']


class DeliveryMethodSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeliveryMethod
        fields = ['id', 'title', 'description']


class RecipientSerializer(serializers.ModelSerializer):
    userId = serializers.PrimaryKeyRelatedField(source='user', read_only=True)

    class Meta:
        model = Recipient
        fields = [
            'id', 'userId', 'first_name', 'last_name',
            'middle_name', 'address', 'zip_code', 'phone'
        ]


class GoodNestedSerializer(serializers.ModelSerializer):
    class Meta:
        model = Good
        fields = ['id', 'name', 'price', 'description']


class BasketItemSerializer(serializers.ModelSerializer):
    goodId = serializers.PrimaryKeyRelatedField(
        source='good', queryset=Good.objects.all()
    )
    good = GoodNestedSerializer(read_only=True)

    class Meta:
        model = BasketItem
        fields = ['id', 'goodId', 'good', 'count']


class CheckoutItemSerializer(serializers.ModelSerializer):
    goodId = serializers.PrimaryKeyRelatedField(source='good', read_only=True)

    class Meta:
        model = CheckoutItem
        fields = ['goodId', 'count']


class CheckoutSerializer(serializers.ModelSerializer):
    recipientId = serializers.PrimaryKeyRelatedField(source='recipient', queryset=Recipient.objects.all())
    paymentMethodId = serializers.PrimaryKeyRelatedField(source='payment_method', queryset=PaymentMethod.objects.all())
    deliveryMethodId = serializers.PrimaryKeyRelatedField(source='delivery_method', queryset=DeliveryMethod.objects.all())
    items = CheckoutItemSerializer(many=True, read_only=True)
    status = serializers.CharField(read_only=True)

    class Meta:
        model = Checkout
        fields = [
            'id', 'user', 'recipientId',
            'paymentMethodId', 'deliveryMethodId',
            'payment_total', 'created', 'items', 'status'
        ]
        read_only_fields = ['user', 'created', 'is_paid', 'status']


class TransactionSerializer(serializers.ModelSerializer):
    checkoutId = serializers.PrimaryKeyRelatedField(source='checkout', queryset=Checkout.objects.all())

    class Meta:
        model = Transaction
        fields = [
            'id', 'created', 'updated', 'status', 'amount',
            'checkoutId', 'provider_data'
        ]

    def get_payment_url(self, obj):
        if not obj.provider_data:
            return None
        try:
            data = json.loads(obj.provider_data) if isinstance(obj.provider_data, str) else obj.provider_data
            return data.get('confirmation', {}).get('confirmation_url')
        except Exception:
            return None