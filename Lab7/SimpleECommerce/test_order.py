# test_order.py (Final Definitive Version, NO Mocking)
import pytest
from order_processor import process_order

# --- 测试用例数据库 ---
# 学生只需要在这里添加和修改测试用例即可
test_cases = [
    ("Initial_Cover_Bug1_But_Pass",
     {
         "customer_id": "C_Multi_Item",
         "is_member": False,
         "items": [
             ("P002", 2), # 商品条目1
             ("P002", 1)  # 商品条目2
         ],
         "coupon_code": "HALFPRICE",
         "shipping_address": {"city": "Guangzhou"},
         "is_weekday": True
     },
     {
         "status": "Success",
         "subtotal": 75.0,
         "discount": 37.5, 
         "shipping_cost": 0.0,
         "final_total": 37.50 
     }),

    # --- 在下方开始补充你为提升覆盖率而设计的白盒测试用例 ---
]


@pytest.mark.parametrize("case_id, order_details, expected_result", test_cases)
def test_order_processing_scenarios(case_id, order_details, expected_result):
    """
    一个健robust的测试函数，能自动处理成功和失败两种情况的断言。
    学生只需要填充上面的 test_cases 列表即可。
    """
    actual_result = process_order(order_details)

    # --- 断言部分 ---
    assert actual_result["status"] == expected_result["status"], f"Test case '{case_id}' failed: Status mismatch."
    
    if expected_result["status"] == "Success":
        assert actual_result["subtotal"] == pytest.approx(expected_result["subtotal"]), f"Test case '{case_id}' failed: Subtotal mismatch."
        assert actual_result["discount"] == pytest.approx(expected_result["discount"]), f"Test case '{case_id}' failed: Discount mismatch."
        assert actual_result["shipping_cost"] == pytest.approx(expected_result["shipping_cost"]), f"Test case '{case_id}' failed: Shipping cost mismatch."
        assert actual_result["final_total"] == pytest.approx(expected_result["final_total"]), f"Test case '{case_id}' failed: Final total mismatch."
    
    elif expected_result["status"] == "Error":
        assert "message" in actual_result, f"Test case '{case_id}' failed: Error response should contain a 'message' field."
        assert expected_result["message"] in actual_result["message"], f"Test case '{case_id}' failed: Expected error message snippet not found."
