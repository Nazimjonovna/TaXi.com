from django.contrib import admin
from .models import User, Order, UserOrder
class UserAdmin(admin.ModelAdmin):
    readonly_fields = ('id',)

# admin.site.register(Book, BookAdmin)

# Register your models here.
admin.site.register(User, UserAdmin)
admin.site.register(Order)
admin.site.register(UserOrder)
