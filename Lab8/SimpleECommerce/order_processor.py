# import sys
# sys.path.insert(0, r'path to your project root')

# 模拟数据库
PRODUCT_DATABASE = {
    "P001": {"name": "Laptop", "price": 1200.00, "stock": 10},
    "P002": {"name": "Mouse", "price": 25.00, "stock": 30},
    "P003": {"name": "Keyboard", "price": 75.00, "stock": 0},  # 商品库存为0
}

# 优惠券数据库
COUPON_DATABASE = {
    "SAVE10": {"type": "fixed", "value": 10.00},
    "HALFPRICE": {"type": "percent", "value": 0.50},
}

# 判断是否是会员并返回折扣
def check_member_discount(subtotal, is_member):
    """检查会员是否有折扣"""
    if is_member and subtotal > 100:
        return 10  # 会员订单满100元，折扣10
    return 0  # 否则没有折扣

# 判断商品价格是否符合折扣条件
def check_price_condition(product_price):
    """检查商品价格是否超过100元"""
    return product_price > 100

# 应用折扣
def apply_discount(subtotal, is_member, coupon_code):
    """根据会员状态和优惠券类型应用折扣"""
    if coupon_code == "HALFPRICE" and is_member:
        return subtotal * 0.5  # 会员且使用HALFPRICE优惠券时，打50%折
    elif coupon_code == "SAVE10" and not is_member:
        return subtotal - 10  # 非会员使用SAVE10优惠券时，减去10元
    return subtotal  # 其他情况下返回原价

# 判断运输费用
def check_shipping_cost(subtotal, shipping_address):
    """判断运输费用"""
    if subtotal >= 200 or shipping_address["city"] in ["Guangzhou", "Shenzhen"]:
        return 0  # 满200元或者在特定城市，免运费
    return 10  # 默认运费为10

# 计算最终总价
def calculate_final_total(subtotal, discount, shipping_cost, is_member, coupon_code):
    """计算最终的总价"""
    discounted_price = apply_discount(subtotal, is_member, coupon_code)
    total_after_discount = discounted_price - discount
    total_after_discount = max(0, total_after_discount)  # 保证最终价格不低于0
    final_total = total_after_discount + shipping_cost
    return final_total

# 订单处理逻辑
def process_order(order_details):
    """处理订单并计算相关费用"""
    # 判断订单格式是否正确，检查是否包含必需的字段
    if not isinstance(order_details, dict) or \
       not all(k in order_details for k in ["customer_id", "is_member", "items", "coupon_code", "shipping_address", "is_weekday"]):
        return {"status": "Error", "message": "Invalid order format."}
    
    items = order_details["items"]
    subtotal = 0.0
    error_messages = []

    # 处理每个商品，计算小计并检查库存
    for product_id, quantity in items:
        product = PRODUCT_DATABASE.get(product_id)
        if not product:
            error_messages.append(f"Product '{product_id}' not found.")
            continue
        if product["stock"] < quantity:
            error_messages.append(f"Insufficient stock for {product['name']}. Available: {product['stock']}, Requested: {quantity}.")
            continue
        
        # 使用 check_price_condition 来检查价格
        if check_price_condition(product["price"]):
            print(f"Product {product['name']} price is greater than 100: {product['price']}")
        else:
            print(f"Product {product['name']} price is less than or equal to 100: {product['price']}")

        item_total = product["price"] * quantity
        subtotal += item_total

    # 如果有错误消息，返回错误状态
    if error_messages:
        return {"status": "Error", "message": " ".join(error_messages)}

    # 判断会员折扣
    discount = check_member_discount(subtotal, order_details["is_member"])

    # 判断运输费用
    shipping_cost = check_shipping_cost(subtotal, order_details["shipping_address"])

    # 计算最终总价
    final_total = calculate_final_total(subtotal, discount, shipping_cost, order_details["is_member"], order_details["coupon_code"])

    return {
        "status": "Success",
        "subtotal": subtotal,
        "discount": discount,
        "shipping_cost": shipping_cost,
        "final_total": final_total,
        "items": items
    }
