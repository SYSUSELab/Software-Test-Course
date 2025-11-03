import pytest
from order_processor import process_order

# 测试数据
test_cases = [
    # 一个案例，可以参考
    ("Test_Valid_Order_With_Member_And_Coupon", 
     {"customer_id": "C001", "is_member": True, "items": [("P001", 1), ("P002", 1)], 
      "coupon_code": "HALFPRICE", "shipping_address": {"city": "Guangzhou"}, "is_weekday": True},
     {"status": "Success", "subtotal": 1225.0, "discount": 600.0, "shipping_cost": 0.0, "final_total": 600.0}
    )
    # 你的测试数据
]

@pytest.mark.parametrize("case_id, order_details, expected_result", test_cases)
def test_order_processing_scenarios(case_id, order_details, expected_result):
    actual_result = process_order(order_details)

    # --- 断言部分 ---
    assert actual_result["status"] == expected_result["status"], f"Test case '{case_id}' failed: Status mismatch."
    
    if expected_result["status"] == "Success":
        assert actual_result["subtotal"] == pytest.approx(expected_result["subtotal"], rel=1e-2), f"Test case '{case_id}' failed: Subtotal mismatch."
        assert actual_result["discount"] == pytest.approx(expected_result["discount"], rel=1e-2), f"Test case '{case_id}' failed: Discount mismatch."
        assert actual_result["shipping_cost"] == pytest.approx(expected_result["shipping_cost"], rel=1e-2), f"Test case '{case_id}' failed: Shipping cost mismatch."
        assert actual_result["final_total"] == pytest.approx(expected_result["final_total"], rel=1e-2), f"Test case '{case_id}' failed: Final total mismatch."
    else:
        assert actual_result["message"] == expected_result["message"], f"Test case '{case_id}' failed: Message mismatch."
