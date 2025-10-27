# order_processor.py
# 这是一个简易的电商订单处理系统，其中包含了被植入的BUG，用于白盒测试实验。

# =============================================================================
# 模拟数据库部分
# =============================================================================

# 模拟一个简易的商品数据库
PRODUCT_DATABASE = {
    "P001": {"name": "Laptop", "price": 1200.00, "stock": 10},
    "P002": {"name": "Mouse", "price": 25.00, "stock": 30},
    "P003": {"name": "Keyboard", "price": 75.00, "stock": 0}, # 库存为0的商品，用于测试
}

# 模拟一个优惠券数据库
COUPON_DATABASE = {
    "SAVE10": {"type": "fixed", "value": 10.00},
    "HALFPRICE": {"type": "percent", "value": 0.50},
}


# =============================================================================
# 核心处理函数
# =============================================================================

def process_order(order_details):
    """
    处理一笔电商订单。
    
    Args:
        order_details (dict): 包含订单所有信息的字典。
    
    Returns:
        dict: 包含处理结果的字典。
    """

    # -------------------------------------------------------------------------
    # 模块 1: 输入验证
    # 功能描述:
    #   这是订单处理的第一道关卡。本模块负责检查传入的订单数据格式是否完整、合法。
    #   它会验证订单本身是否为字典、是否包含所有必需的字段（如客户ID、商品列表等），
    #   并确保商品列表不为空、is_weekday标记为布尔值。
    #   如果任何一项检查失败，函数将立即返回错误，不再继续处理。
    # -------------------------------------------------------------------------
    if not isinstance(order_details, dict) or \
       not all(k in order_details for k in ["customer_id", "is_member", "items", "coupon_code", "shipping_address", "is_weekday"]):
        return {"status": "Error", "message": "Invalid order format."}
    if not isinstance(order_details["is_weekday"], bool):
        return {"status": "Error", "message": "is_weekday must be a boolean."}

    items = order_details["items"]
    if not isinstance(items, list) or not items:
        return {"status": "Error", "message": "Order must contain at least one item."}
    
    # 初始化账单变量
    subtotal = 0.0
    processed_items = []
    error_messages = []

    # -------------------------------------------------------------------------
    # 模块 2: 商品处理与库存检查
    # 功能描述:
    #   本模块是订单处理的核心，它会逐一检查订单中的每一件商品。
    #   对于每件商品，它会验证数据格式（如数量是否为正整数），并查询数据库以确认商品是否存在、库存是否充足。
    #   所有检查通过的商品，其价格会被累加到商品总价(subtotal)中。
    #   如果在此过程中发现任何错误，系统应记录下所有错误信息，并在检查完所有商品后统一返回。
    # -------------------------------------------------------------------------
    for product_id, quantity in items:
        
        if not (isinstance(product_id, str) and isinstance(quantity, int) and quantity > 0):
            return {"status": "Error", "message": f"Invalid item data for product '{product_id}'."}
        
        product = PRODUCT_DATABASE.get(product_id)
        if not product:
            error_messages.append(f"Product '{product_id}' not found.")
            continue
            
        if product["stock"] < quantity:
            error_messages.append(f"Insufficient stock for {product['name']}. Available: {product['stock']}, Requested: {quantity}.")
            continue
        
        item_total = product["price"] * quantity
        subtotal += item_total
        processed_items.append({"name": product["name"], "quantity": quantity, "total": item_total})

    if error_messages:
        return {"status": "Error", "message": " ".join(error_messages)}
    
    # -------------------------------------------------------------------------
    # 模块 3: 折扣计算
    # 功能描述:
    #   在计算出商品总价后，本模块会应用各种折扣规则。
    #   它首先会处理订单中可能存在的优惠券，分为“固定金额”和“百分比”两种类型。
    #   其中，百分比折扣券有一个最低消费门槛。
    #   接着，系统会为满足特定条件（会员、消费额、工作日）的会员顾客提供一笔额外的专属折扣。
    #   所有折扣会累加，并确保最终价格不为负数。
    # -------------------------------------------------------------------------
    discount_amount = 0.0
    coupon_code = order_details["coupon_code"]
    
    if coupon_code and coupon_code in COUPON_DATABASE:
        coupon = COUPON_DATABASE[coupon_code]
        if coupon["type"] == "fixed":
            discount_amount = coupon["value"]
        elif coupon["type"] == "percent":
            if len(order_details["items"]) > 1 and subtotal > 50.0:
                discount_amount = subtotal * coupon["value"]
            
    is_member = order_details["is_member"]
    is_weekday = order_details["is_weekday"]
    if is_member and subtotal > 100.0 and is_weekday:
        discount_amount = 5.00
    
    total_after_discount = subtotal - discount_amount
    if total_after_discount < 0:
        total_after_discount = 0

    # -------------------------------------------------------------------------
    # 模块 4: 运费计算
    # 功能描述:
    #   本模块负责计算订单的运费。系统有一个默认的基础运费。
    #   但是，如果订单满足特定的包邮条件（如消费金额达到某一阈值，或收货地址在特定城市），
    #   运费将被减免为零。
    # -------------------------------------------------------------------------
    shipping_cost = 10.0
    city = order_details["shipping_address"].get("city")
    if total_after_discount >= 200.0 or city in ["Guangzhou", "Shenzhen"]:
        shipping_cost = 0.0

    # -------------------------------------------------------------------------
    # 模块 5: 生成最终账单
    # 功能描述:
    #   这是订单处理的最后一步。本模块将折扣后的价格与运费相加，得到最终应付总额。
    #   然后，它会将所有计算结果（商品总价、折扣金额、运费、最终总额等）
    #   打包成一个结构化的字典并返回，作为本次订单处理的成功凭证。
    # -------------------------------------------------------------------------
    final_total = total_after_discount + shipping_cost
    
    return {
        "status": "Success",
        "subtotal": subtotal,
        "discount": discount_amount,
        "shipping_cost": shipping_cost,
        "final_total": final_total,
        "items": processed_items
    }
