# order_processor.py
import datetime

# 模拟一个简易的商品数据库
PRODUCT_DATABASE = {
    "P001": {"name": "Laptop", "price": 1200.00, "stock": 10},
    "P002": {"name": "Mouse", "price": 25.00, "stock": 30},
    "P003": {"name": "Keyboard", "price": 75.00, "stock": 0}, # 库存为0
}

# 模拟一个优惠券数据库
COUPON_DATABASE = {
    "SAVE10": {"type": "fixed", "value": 10.00},
    "HALFPRICE": {"type": "percent", "value": 0.50},
}

def process_order(order_details):
    """
    处理一笔电商订单。
    order_details 是一个字典，包含:
    - "customer_id": 客户ID (str)
    - "is_member": 是否为会员 (bool)
    - "items": 商品列表，每个元素是 (product_id, quantity) 的元组
    - "coupon_code": 优惠券代码 (str or None)
    - "shipping_address": 收货地址 (dict with "city")
    """
    # 1. --- 输入验证 ---
    if not isinstance(order_details, dict) or \
       not all(k in order_details for k in ["customer_id", "is_member", "items", "coupon_code", "shipping_address"]):
        return {"status": "Error", "message": "Invalid order format."}

    items = order_details["items"]
    if not isinstance(items, list) or not items:
        return {"status": "Error", "message": "Order must contain at least one item."}
    
    # --- 初始化账单 ---
    subtotal = 0.0
    processed_items = []
    error_messages = []

    # 2. --- 商品处理与库存检查 ---
    for product_id, quantity in items:
        if not (isinstance(product_id, str) and isinstance(quantity, int) and quantity > 0):
            error_messages.append(f"Invalid item data for product '{product_id}'.")
            continue
            
        product = PRODUCT_DATABASE.get(product_id)
        if not product:
            error_messages.append(f"Product '{product_id}' not found.")
            continue
        
        if product["stock"] < quantity:
            error_messages.append(f"Insufficient stock for {product['name']}. Available: {product['stock']}, Requested: {quantity}.")
            continue
        
        # 计算小计
        item_total = product["price"] * quantity
        subtotal += item_total
        processed_items.append({"name": product["name"], "quantity": quantity, "total": item_total})

    if error_messages:
        return {"status": "Error", "message": " ".join(error_messages)}
    
    # 3. --- 计算折扣 ---
    discount_amount = 0.0
    coupon_code = order_details["coupon_code"]
    
    if coupon_code and coupon_code in COUPON_DATABASE:
        coupon = COUPON_DATABASE[coupon_code]
        if coupon["type"] == "fixed":
            discount_amount = coupon["value"]
        elif coupon["type"] == "percent" and subtotal > 50.0: # 百分比折扣有最低消费门槛
            discount_amount = subtotal * coupon["value"]
            
    # 会员折扣：会员在非周末（周一到周五）购物，且消费满100元，可享额外5元折扣
    is_member = order_details["is_member"]
    is_weekday = datetime.date.today().weekday() < 5 # Monday is 0 and Sunday is 6
    if is_member and subtotal > 100.0 and is_weekday:
        discount_amount += 5.00
    
    total_after_discount = subtotal - discount_amount
    if total_after_discount < 0:
        total_after_discount = 0

    # 4. --- 计算运费 ---
    shipping_cost = 10.0 # 默认运费
    city = order_details["shipping_address"].get("city")
    
    # 满200元包邮，或特定城市包邮
    if total_after_discount >= 200.0 or city in ["Guangzhou", "Shenzhen"]:
        shipping_cost = 0.0

    # 5. --- 生成最终账单 ---
    final_total = total_after_discount + shipping_cost
    
    return {
        "status": "Success",
        "subtotal": subtotal,
        "discount": discount_amount,
        "shipping_cost": shipping_cost,
        "final_total": round(final_total, 2),
        "items": processed_items
    }