# test_order.py
import pytest
from order_processor import process_order
import datetime


# 学生只需要在这里添加和修改测试用例即可
# 每个元组的结构: (测试用例ID, 订单字典, 期望结果字典)
test_cases = [
    ("Test_0", 
     {
         "customer_id": "C123",
         "is_member": False,
         "items": [("P001", 1)], 
         "coupon_code": None,
         "shipping_address": {"city": "Beijing"}
     },
     {
         "status": "Success",
         "subtotal": 1200.00,
         "discount": 0.0,
         "shipping_cost": 0.0,
         "final_total": 1200.00
     })
    # ... 学生在此处继续添加设计的测试用例 ...
]


@pytest.mark.parametrize("case_id, order_details, expected_result", test_cases)
def test_order_processing_scenarios(case_id, order_details, expected_result):
    """
    一个健壮的测试函数，能自动处理成功和失败两种情况的断言。
    学生只需要填充上面的 test_cases 列表即可。
    """

    actual_result = process_order(order_details)

    assert actual_result["status"] == expected_result["status"], \
        f"Test case '{case_id}' failed: Status mismatch."

    if expected_result["status"] == "Success":

        assert actual_result["subtotal"] == pytest.approx(expected_result["subtotal"]), \
            f"Test case '{case_id}' failed: Subtotal mismatch."
        assert actual_result["discount"] == pytest.approx(expected_result["discount"]), \
            f"Test case '{case_id}' failed: Discount mismatch."
        assert actual_result["shipping_cost"] == pytest.approx(expected_result["shipping_cost"]), \
            f"Test case '{case_id}' failed: Shipping cost mismatch."
        assert actual_result["final_total"] == pytest.approx(expected_result["final_total"]), \
            f"Test case '{case_id}' failed: Final total mismatch."
    
    elif expected_result["status"] == "Error":

        assert "message" in actual_result, \
            f"Test case '{case_id}' failed: Error response should contain a 'message' field."
        assert expected_result["message"] in actual_result["message"], \
            f"Test case '{case_id}' failed: Expected error message snippet not found. " \
            f"Expected '{expected_result['message']}' to be in '{actual_result['message']}'."