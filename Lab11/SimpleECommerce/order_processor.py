# order_processor.py

# =============================================================================
# 全局数据模拟
# =============================================================================
PRODUCT_DATABASE = {
    "P001": {"name": "Laptop", "price": 1200.00, "stock": 10},
    "P002": {"name": "Mouse", "price": 25.00, "stock": 30},
    "P003": {"name": "Keyboard", "price": 75.00, "stock": 0}, 
}

COUPON_DATABASE = {
    "SAVE10": {"type": "fixed", "value": 10.00},
    "HALFPRICE": {"type": "percent", "value": 0.50},
}

# =============================================================================
# 单元功能函数
# =============================================================================

def validate_order_format(order):
    required_keys = ["customer_id", "is_member", "items", "coupon_code", "shipping_address", "is_weekday"]
    if not isinstance(order, dict):
        return False, "Invalid order format."
    if not all(k in order for k in required_keys):
        return False, "Missing required fields."
    if not isinstance(order["is_weekday"], bool):
        return False, "is_weekday must be a boolean."
    if not isinstance(order["items"], list) or not order["items"]:
        return False, "Order must contain at least one item."
    return True, ""

def calculate_item_subtotal(items):
    """
    计算商品总价并扣减库存。
    """
    subtotal = 0.0
    processed_items = []
    errors = []

    for product_id, quantity in items:
        if not (isinstance(product_id, str) and isinstance(quantity, int) and quantity > 0):

            return 0, [], [f"Invalid item data for product '{product_id}'."] 

        product = PRODUCT_DATABASE.get(product_id)
        if not product:
            errors.append(f"Product '{product_id}' not found.")
            continue
            
        if product["stock"] < quantity:
            errors.append(f"Insufficient stock for {product['name']}.")
            continue
        
        item_total = product["price"] * quantity
        subtotal += item_total
        processed_items.append({"name": product["name"], "quantity": quantity, "total": item_total})
        
    return subtotal, processed_items, errors

def calculate_discount(subtotal, items, coupon_code, is_member, is_weekday):
    """
    计算折扣。
    """
    discount = 0.0
    
    # 1. 优惠券逻辑
    if coupon_code and coupon_code in COUPON_DATABASE:
        coupon = COUPON_DATABASE[coupon_code]
        if coupon["type"] == "fixed":
            discount += coupon["value"]
        elif coupon["type"] == "percent":

            if len(items) > 1 and subtotal > 50.0:
                discount += subtotal * coupon["value"]
            
    # 2. 会员折扣逻辑
    if is_member and subtotal > 100.0 and is_weekday:

        discount = 5.00  
    
    # 兜底逻辑
    if discount > subtotal:
        discount = subtotal
        
    return discount

def calculate_shipping(total_after_discount, address):
    shipping_cost = 10.0
    city = address.get("city")
    # 满 200 或 指定城市免邮
    if total_after_discount >= 200.0 or city in ["Guangzhou", "Shenzhen"]:
        shipping_cost = 0.0
    return shipping_cost

# =============================================================================
# 主流程函数
# =============================================================================

def process_order(order_details):
    is_valid, error_msg = validate_order_format(order_details)
    if not is_valid:
        return {"status": "Error", "message": error_msg}
    
    subtotal, processed_items, item_errors = calculate_item_subtotal(order_details["items"])
    if item_errors:
        return {"status": "Error", "message": " ".join(item_errors)}
    
    discount_amount = calculate_discount(
        subtotal, 
        order_details["items"], 
        order_details["coupon_code"],
        order_details["is_member"],
        order_details["is_weekday"]
    )
    
    total_after_discount = subtotal - discount_amount
    shipping_cost = calculate_shipping(total_after_discount, order_details["shipping_address"])
    final_total = total_after_discount + shipping_cost
    
    return {
        "status": "Success",
        "subtotal": subtotal,
        "discount": discount_amount,
        "shipping_cost": shipping_cost,
        "final_total": final_total,
        "items": processed_items
    }